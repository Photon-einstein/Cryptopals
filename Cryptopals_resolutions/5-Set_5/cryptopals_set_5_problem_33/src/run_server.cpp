#include <iostream>
#include <map>
#include <memory>
#include <string>
#include <time.h>
#include <vector>

int main(void) {
  clock_t start, end;
  double time;
  start = clock();
  /* work to verify */

  /* end of the work */
  end = clock();
  time = (double)(end - start) / CLOCKS_PER_SEC;
  printf("\nProgram took %f s.", time);
  printf("\n");
  return 0;
}
/******************************************************************************/