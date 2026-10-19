#include <erl_nif.h>

#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* feature bitmap の各 bit を個別の feature として登録する数 */
#define FEATURE_BIT_COUNT 64
/* feature bitmap 全体のハッシュを格納するカウンター数 */
#define FEATURE_HASH_COUNT 65536
#define FEATURE_COUNTER_COUNT (FEATURE_BIT_COUNT + FEATURE_HASH_COUNT)

struct fuzz_context {
  ErlNifMutex* mutex;
  ErlNifCond* condition;
  ErlNifPid worker;
  ErlNifMonitor worker_monitor;
  int awaiting_reply;
  int replied;
  int crashed;
  int timed_out;
  uint64_t features;
};

static ErlNifResourceType* context_resource_type;
static ErlNifMutex* active_context_mutex;
static struct fuzz_context* active_context;
static _Thread_local jmp_buf* driver_exit_jump;
static _Thread_local int driver_exit_status;

/* libFuzzer に登録する feature カウンター。
   先頭 FEATURE_BIT_COUNT 個は feature bitmap の各 bit を表し、
   残りは bitmap 全体のハッシュを格納する。 */
static uint8_t feature_counters[FEATURE_COUNTER_COUNT];
/* libFuzzer はカウンター数と PC テーブル数が一致することを検査する。
   独自に登録するカウンターにもダミーの PC テーブルを用意する。 */
static const uintptr_t feature_pcs[FEATURE_COUNTER_COUNT * 2];
static size_t last_feature_hash_index = SIZE_MAX;
static int feature_counters_registered = 0;

extern void __sanitizer_cov_8bit_counters_init(uint8_t* start, uint8_t* stop);
extern void __sanitizer_cov_pcs_init(const uintptr_t* pcs_beg,
                                     const uintptr_t* pcs_end);

/* LLVMFuzzerRunDriver は fuzzing ループの終了時に exit() を呼ぶ。
   有限回の実行で BEAM に戻れるように、この制御フローを NIF 内に閉じ込める。 */
__attribute__((visibility("hidden"))) void exit(int status) {
  if (driver_exit_jump != NULL) {
    driver_exit_status = status;
    longjmp(*driver_exit_jump, 1);
  }
  _Exit(status);
}

/* ドライバーは意図的に自身の状態を解放せず、終了ハンドラーを登録する。
   NIF の寿命は BEAM が管理するため、ここでは登録しない。 */
__attribute__((visibility("hidden"))) int atexit(void (*callback)(void)) {
  (void)callback;
  return 0;
}

extern int LLVMFuzzerRunDriver(int* argc,
                               char*** argv,
                               int (*callback)(const uint8_t* data,
                                               size_t size));

static void context_destructor(ErlNifEnv* env, void* object) {
  struct fuzz_context* context = object;

  (void)env;
  if (context->condition != NULL) {
    enif_cond_destroy(context->condition);
  }
  if (context->mutex != NULL) {
    enif_mutex_destroy(context->mutex);
  }
}

static void context_down(ErlNifEnv* env,
                         void* object,
                         ErlNifPid* pid,
                         ErlNifMonitor* monitor) {
  struct fuzz_context* context = object;

  (void)env;
  (void)pid;
  (void)monitor;
  enif_mutex_lock(context->mutex);
  if (context->awaiting_reply && !context->replied) {
    context->crashed = 1;
    context->features = 0;
    context->replied = 1;
    enif_cond_signal(context->condition);
  }
  enif_mutex_unlock(context->mutex);
}

/* feature bitmap 全体をハッシュし、bit の組み合わせを 1 つの feature にする。
   SplitMix64 の最終混合処理を使う。 */
static uint64_t hash_features(uint64_t features) {
  uint64_t hash = features;

  hash ^= hash >> 33;
  hash *= UINT64_C(0xff51afd7ed558ccd);
  hash ^= hash >> 33;
  hash *= UINT64_C(0xc4ceb9fe1a85ec53);
  hash ^= hash >> 33;
  return hash;
}

/* libFuzzer のカウンター領域を一度だけ登録する。
   登録したカウンターは libFuzzer が入力ごとに収集する。 */
static void register_feature_counters(void) {
  if (!feature_counters_registered) {
    __sanitizer_cov_8bit_counters_init(
        feature_counters, feature_counters + FEATURE_COUNTER_COUNT);
    __sanitizer_cov_pcs_init(feature_pcs,
                             feature_pcs + FEATURE_COUNTER_COUNT * 2);
    feature_counters_registered = 1;
  }
}

/* Erlang から返された feature bitmap を libFuzzer のカウンターへ反映する。
   - 各 bit は個別の feature になる
   - bitmap 全体のハッシュは bit の組み合わせを表す feature になる
   前回のハッシュカウンターだけは、入力ごとの組み合わせを正しく扱うために下ろす。 */
static void report_features(uint64_t features) {
  int bit;
  size_t hash_index;

  if (last_feature_hash_index != SIZE_MAX) {
    feature_counters[last_feature_hash_index] = 0;
  }

  for (bit = 0; bit < FEATURE_BIT_COUNT; bit++) {
    if ((features & (UINT64_C(1) << bit)) != 0) {
      feature_counters[bit] = 1;
    }
  }

  hash_index = FEATURE_BIT_COUNT +
               (size_t)(hash_features(features) % FEATURE_HASH_COUNT);
  feature_counters[hash_index] = 1;
  last_feature_hash_index = hash_index;
}

static void free_partial_argv(char** strings,
                              unsigned int string_count,
                              char** argv,
                              char** argv_copy) {
  unsigned int i;

  for (i = 0; i < string_count; i++) {
    enif_free(strings[i]);
  }
  enif_free(strings);
  enif_free(argv);
  enif_free(argv_copy);
}

/* Erlang のバイナリーリストを libFuzzer 用の argv に変換する。
   戻り値は 1 が成功、0 が不正な引数、-1 がメモリー不足。
   strings は個々の文字列の所有権を保持し、argv と argv_copy は同じ文字列を指す。 */
static int build_argv(ErlNifEnv* env,
                      ERL_NIF_TERM list,
                      char*** out_argv,
                      char*** out_argv_copy,
                      char*** out_strings,
                      int* out_argc,
                      int* out_string_count) {
  ErlNifBinary binary;
  ERL_NIF_TERM head;
  ERL_NIF_TERM tail = list;
  char** strings;
  char** argv;
  char** argv_copy;
  unsigned int length;
  unsigned int i;

  if (!enif_get_list_length(env, list, &length)) {
    return 0;
  }
  strings = enif_alloc(sizeof(char*) * (length == 0 ? 1 : length));
  argv = enif_alloc(sizeof(char*) * (length + 2));
  argv_copy = enif_alloc(sizeof(char*) * (length + 2));
  if (strings == NULL || argv == NULL || argv_copy == NULL) {
    if (strings != NULL) {
      enif_free(strings);
    }
    if (argv != NULL) {
      enif_free(argv);
    }
    if (argv_copy != NULL) {
      enif_free(argv_copy);
    }
    return -1;
  }

  argv[0] = (char*)"erlang_fuzzer";
  for (i = 0; i < length; i++) {
    if (!enif_get_list_cell(env, tail, &head, &tail) ||
        !enif_inspect_binary(env, head, &binary) ||
        (binary.size > 0 && memchr(binary.data, '\0', binary.size) != NULL)) {
      free_partial_argv(strings, i, argv, argv_copy);
      return 0;
    }
    strings[i] = enif_alloc(binary.size + 1);
    if (strings[i] == NULL) {
      free_partial_argv(strings, i, argv, argv_copy);
      return -1;
    }
    memcpy(strings[i], binary.data, binary.size);
    strings[i][binary.size] = '\0';
    argv[i + 1] = strings[i];
  }
  argv[length + 1] = NULL;
  memcpy(argv_copy, argv, sizeof(char*) * (length + 2));

  *out_argv = argv;
  *out_argv_copy = argv_copy;
  *out_strings = strings;
  *out_argc = (int)length + 1;
  *out_string_count = (int)length;
  return 1;
}

static void free_argv(char** strings,
                      int string_count,
                      char** argv,
                      char** argv_copy) {
  int i;

  for (i = 0; i < string_count; i++) {
    enif_free(strings[i]);
  }
  enif_free(strings);
  enif_free(argv);
  enif_free(argv_copy);
}

static int fuzz_callback(const uint8_t* data, size_t size) {
  struct fuzz_context* context = active_context;
  ErlNifEnv* message_env;
  ERL_NIF_TERM context_term;
  ERL_NIF_TERM data_term;
  ERL_NIF_TERM message;
  unsigned char* binary_data;
  int crashed;
  uint64_t features;

  if (context == NULL) {
    abort();
  }

  enif_mutex_lock(context->mutex);
  context->awaiting_reply = 1;
  context->replied = 0;
  enif_mutex_unlock(context->mutex);

  message_env = enif_alloc_env();
  if (message_env == NULL) {
    abort();
  }
  binary_data = enif_make_new_binary(message_env, size, &data_term);
  if (size > 0 && binary_data == NULL) {
    enif_free_env(message_env);
    abort();
  }
  if (size > 0) {
    memcpy(binary_data, data, size);
  }
  context_term = enif_make_resource(message_env, context);
  message =
      enif_make_tuple3(message_env, enif_make_atom(message_env, "fuzz_input"),
                       context_term, data_term);
  if (!enif_send(NULL, &context->worker, message_env, message)) {
    enif_free_env(message_env);
    abort();
  }
  enif_free_env(message_env);

  enif_mutex_lock(context->mutex);
  while (!context->replied) {
    enif_cond_wait(context->condition, context->mutex);
  }
  crashed = context->crashed;
  features = context->features;
  context->awaiting_reply = 0;
  enif_mutex_unlock(context->mutex);

  if (crashed) {
    fprintf(stderr, "fuzzer: %s\n",
            context->timed_out ? "input timeout" : "worker down");
    abort();
  }
  report_features(features);
  return 0;
}

static ERL_NIF_TERM run_nif(ErlNifEnv* env,
                            int argc,
                            const ERL_NIF_TERM argv[]) {
  struct fuzz_context* context;
  ErlNifPid worker;
  char** driver_argv = NULL;
  char** driver_argv_copy = NULL;
  char** driver_strings = NULL;
  int driver_argc = 0;
  int driver_string_count = 0;
  int build_result;
  jmp_buf exit_jump;
  int result;

  if (argc != 2 || !enif_get_local_pid(env, argv[0], &worker)) {
    return enif_make_badarg(env);
  }

  build_result =
      build_argv(env, argv[1], &driver_argv, &driver_argv_copy, &driver_strings,
                 &driver_argc, &driver_string_count);
  if (build_result == 0) {
    return enif_make_badarg(env);
  }
  if (build_result < 0) {
    return enif_raise_exception(env, enif_make_atom(env, "enomem"));
  }

  context = enif_alloc_resource(context_resource_type, sizeof(*context));
  if (context == NULL) {
    free_argv(driver_strings, driver_string_count, driver_argv,
              driver_argv_copy);
    return enif_raise_exception(env, enif_make_atom(env, "enomem"));
  }
  memset(context, 0, sizeof(*context));
  context->worker = worker;
  context->mutex = enif_mutex_create("fuzzer_context_mutex");
  context->condition = enif_cond_create("fuzzer_context_condition");
  if (context->mutex == NULL || context->condition == NULL) {
    enif_release_resource(context);
    free_argv(driver_strings, driver_string_count, driver_argv,
              driver_argv_copy);
    return enif_raise_exception(env, enif_make_atom(env, "enomem"));
  }
  if (enif_monitor_process(env, context, &worker, &context->worker_monitor) !=
      0) {
    enif_release_resource(context);
    free_argv(driver_strings, driver_string_count, driver_argv,
              driver_argv_copy);
    return enif_raise_exception(env, enif_make_atom(env, "worker_down"));
  }

  enif_mutex_lock(active_context_mutex);
  if (active_context != NULL) {
    enif_mutex_unlock(active_context_mutex);
    enif_release_resource(context);
    free_argv(driver_strings, driver_string_count, driver_argv,
              driver_argv_copy);
    return enif_raise_exception(env, enif_make_atom(env, "busy"));
  }
  active_context = context;
  enif_mutex_unlock(active_context_mutex);

  register_feature_counters();
  memset(feature_counters, 0, sizeof(feature_counters));
  last_feature_hash_index = SIZE_MAX;

  driver_exit_jump = &exit_jump;
  if (setjmp(exit_jump) == 0) {
    char** driver_argv_pointer = driver_argv_copy;
    int driver_argc_copy = driver_argc;
    result = LLVMFuzzerRunDriver(&driver_argc_copy, &driver_argv_pointer,
                                 fuzz_callback);
  } else {
    result = driver_exit_status;
  }
  driver_exit_jump = NULL;

  enif_mutex_lock(active_context_mutex);
  active_context = NULL;
  enif_mutex_unlock(active_context_mutex);
  enif_demonitor_process(env, context, &context->worker_monitor);
  enif_release_resource(context);
  free_argv(driver_strings, driver_string_count, driver_argv, driver_argv_copy);
  return enif_make_int(env, result);
}

static ERL_NIF_TERM reply_nif(ErlNifEnv* env,
                              int argc,
                              const ERL_NIF_TERM argv[]) {
  struct fuzz_context* context;
  ErlNifUInt64 features;
  int crashed;

  if (argc != 2 || !enif_get_resource(env, argv[0], context_resource_type,
                                      (void**)&context)) {
    return enif_make_badarg(env);
  }

  crashed = enif_is_identical(argv[1], enif_make_atom(env, "crash"));
  if (!crashed && !enif_get_uint64(env, argv[1], &features)) {
    return enif_make_badarg(env);
  }

  enif_mutex_lock(context->mutex);
  if (!context->awaiting_reply || context->replied) {
    enif_mutex_unlock(context->mutex);
    return enif_raise_exception(env, enif_make_atom(env, "stale_reply"));
  }
  context->crashed = crashed;
  context->features = crashed ? 0 : features;
  context->replied = 1;
  enif_cond_signal(context->condition);
  enif_mutex_unlock(context->mutex);
  return enif_make_atom(env, "ok");
}

/* 入力タイムアウトを記録する。ここではまだコールバックを起こさない。
   呼び出し側がレポートを書いた後に abort_timeout/1 で起こす。 */
static ERL_NIF_TERM timeout_nif(ErlNifEnv* env,
                                int argc,
                                const ERL_NIF_TERM argv[]) {
  struct fuzz_context* context;
  int timed_out = 0;

  if (argc != 1 || !enif_get_resource(env, argv[0], context_resource_type,
                                      (void**)&context)) {
    return enif_make_badarg(env);
  }

  enif_mutex_lock(context->mutex);
  if (context->awaiting_reply && !context->replied) {
    context->crashed = 1;
    context->timed_out = 1;
    context->features = 0;
    context->replied = 1;
    timed_out = 1;
  }
  enif_mutex_unlock(context->mutex);
  return enif_make_atom(env, timed_out ? "timeout" : "ok");
}

/* timeout_nif/1 で記録したタイムアウトをコールバックへ通知する。 */
static ERL_NIF_TERM abort_timeout_nif(ErlNifEnv* env,
                                      int argc,
                                      const ERL_NIF_TERM argv[]) {
  struct fuzz_context* context;

  if (argc != 1 || !enif_get_resource(env, argv[0], context_resource_type,
                                      (void**)&context)) {
    return enif_make_badarg(env);
  }

  enif_mutex_lock(context->mutex);
  if (context->timed_out) {
    enif_cond_signal(context->condition);
  }
  enif_mutex_unlock(context->mutex);
  return enif_make_atom(env, "ok");
}

static int load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info) {
  ErlNifResourceTypeInit resource_type_init = {context_destructor, NULL,
                                               context_down, 0, NULL};

  (void)priv_data;
  (void)load_info;
  context_resource_type = enif_open_resource_type_x(
      env, "fuzzer_context", &resource_type_init, ERL_NIF_RT_CREATE, NULL);
  active_context_mutex = enif_mutex_create("fuzzer_active_context_mutex");
  return context_resource_type != NULL && active_context_mutex != NULL ? 0 : -1;
}

static void unload(ErlNifEnv* env, void* priv_data) {
  (void)env;
  (void)priv_data;
  enif_mutex_destroy(active_context_mutex);
}

static ErlNifFunc nif_funcs[] = {
    {"run_nif", 2, run_nif, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"reply", 2, reply_nif, 0},
    {"timeout", 1, timeout_nif, 0},
    {"abort_timeout", 1, abort_timeout_nif, 0}};

ERL_NIF_INIT(fuzzer, nif_funcs, load, NULL, NULL, unload)
