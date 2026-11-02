/* Test target for ps5-perf: known CPU distribution.
 *   thread "burn-main":  ~75% of its time in hot_a(), ~25% in hot_b()
 *                        (both called through mid_level() -> outer())
 *   thread "burn-half":  busy 50% (cold_spin), sleeping 50%
 *   thread "burn-idle":  sleeps
 * Runs for 120 seconds. */
#include <pthread.h>
#include <pthread_np.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

static volatile uint64_t sink;

static uint64_t now_us(void) {
  struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
  return ts.tv_sec * 1000000ull + ts.tv_nsec / 1000;
}
__attribute__((noinline)) static void spin_us(uint64_t us) {
  uint64_t end = now_us() + us;
  while(now_us() < end) for(int i = 0; i < 200; i++) sink += i;
}
__attribute__((noinline)) void hot_a(void) { spin_us(3000); }
__attribute__((noinline)) void hot_b(void) { spin_us(1000); }
__attribute__((noinline)) void mid_level(int i) { if(i & 1) hot_a(); else { hot_a(); hot_b(); hot_b(); hot_a(); } }
__attribute__((noinline)) void outer(int i) { mid_level(i); }
__attribute__((noinline)) void cold_spin(void) { spin_us(5000); }

static void *half(void *a) {
  pthread_set_name_np(pthread_self(), "burn-half");
  for(;;) { cold_spin(); usleep(5000); }
}
static void *idle(void *a) {
  pthread_set_name_np(pthread_self(), "burn-idle");
  for(;;) sleep(1);
}
int main(void) {
  pthread_t t;
  pthread_set_name_np(pthread_self(), "burn-main");
  pthread_create(&t, 0, half, 0);
  pthread_create(&t, 0, idle, 0);
  #ifndef RUN_SECS
#define RUN_SECS 120
#endif
  uint64_t end = now_us() + RUN_SECS * 1000000ull;
  for(int i = 0; now_us() < end; i++) outer(i);
  return 0;
}
