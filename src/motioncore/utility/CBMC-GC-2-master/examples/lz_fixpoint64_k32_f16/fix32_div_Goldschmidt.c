#include "fix32.h"

// vodi main(){
void mpc_main() {

  fixedptd INPUT_A_x;
  fixedptd INPUT_B_x;

  fixedptd OUTPUT_div_Goldschmidt = fixedptd_div_Goldschmidt(INPUT_A_x, INPUT_B_x);
}

