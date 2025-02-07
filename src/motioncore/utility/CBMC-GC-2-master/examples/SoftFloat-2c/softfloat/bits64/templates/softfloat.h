
/*============================================================================

This C header file template is part of the Berkeley SoftFloat IEEE Floating-
Point Arithmetic Package, Release 2c, by John R. Hauser.

THIS SOFTWARE IS DISTRIBUTED AS IS, FOR FREE.  Although reasonable effort has
been made to avoid it, THIS SOFTWARE MAY CONTAIN FAULTS THAT WILL AT TIMES
RESULT IN INCORRECT BEHAVIOR.  USE OF THIS SOFTWARE IS RESTRICTED TO PERSONS
AND ORGANIZATIONS WHO CAN AND WILL TOLERATE ALL LOSSES, COSTS, OR OTHER
PROBLEMS THEY INCUR DUE TO THE SOFTWARE WITHOUT RECOMPENSE FROM JOHN HAUSER OR
THE INTERNATIONAL COMPUTER SCIENCE INSTITUTE, AND WHO FURTHERMORE EFFECTIVELY
INDEMNIFY JOHN HAUSER AND THE INTERNATIONAL COMPUTER SCIENCE INSTITUTE
(possibly via similar legal notice) AGAINST ALL LOSSES, COSTS, OR OTHER
PROBLEMS INCURRED BY THEIR CUSTOMERS AND CLIENTS DUE TO THE SOFTWARE, OR
INCURRED BY ANYONE DUE TO A DERIVATIVE WORK THEY CREATE USING ANY PART OF THE
SOFTWARE.

Derivative works require also that (1) the source code for the derivative work
includes prominent notice that the work is derivative, and (2) the source code
includes prominent notice of these three paragraphs for those parts of this
code that are retained.

=============================================================================*/

/*----------------------------------------------------------------------------
| The macro `FLOATX80' must be defined to enable the double-extended-precision
| floating-point format `floatx80'.  If this macro is not defined, the
| `floatx80' type will not be defined, and none of the functions that either
| input or output the `floatx80' type will be defined.  The same applies to
| the `FLOAT128' macro and the quadruple-precision format `float128'.
*----------------------------------------------------------------------------*/
#define FLOATX80
#define FLOAT128

/*----------------------------------------------------------------------------
| Software IEEE floating-point types.
*----------------------------------------------------------------------------*/
typedef !!!bits32 float32;
typedef !!!bits64 float64;
#ifdef FLOATX80
typedef struct {
    !!!bits16 high;
    !!!bits64 low;
} floatx80;
#endif
#ifdef FLOAT128
typedef struct {
    !!!bits64 high, low;
} float128;
#endif

/*----------------------------------------------------------------------------
| Software IEEE floating-point underflow tininess-detection mode.
*----------------------------------------------------------------------------*/
extern !!!int8 float_detect_tininess;
enum {
    float_tininess_after_rounding  = 0,
    float_tininess_before_rounding = 1
};

/*----------------------------------------------------------------------------
| Software IEEE floating-point rounding mode.
*----------------------------------------------------------------------------*/
extern !!!int8 float_rounding_mode;
enum {
    float_round_nearest_even = 0,
    float_round_to_zero      = 1,
    float_round_down         = 2,
    float_round_up           = 3
};

/*----------------------------------------------------------------------------
| Software IEEE floating-point exception flags.
*----------------------------------------------------------------------------*/
extern !!!int8 float_exception_flags;
enum {
    float_flag_inexact   =  1,
    float_flag_underflow =  2,
    float_flag_overflow  =  4,
    float_flag_divbyzero =  8,
    float_flag_invalid   = 16
};

/*----------------------------------------------------------------------------
| Routine to raise any or all of the software IEEE floating-point exception
| flags.
*----------------------------------------------------------------------------*/
void float_raise( !!!int8 );

/*----------------------------------------------------------------------------
| Software IEEE integer-to-floating-point conversion routines.
*----------------------------------------------------------------------------*/
float32 int32_to_float32( !!!int32 );
float64 int32_to_float64( !!!int32 );
#ifdef FLOATX80
floatx80 int32_to_floatx80( !!!int32 );
#endif
#ifdef FLOAT128
float128 int32_to_float128( !!!int32 );
#endif
float32 int64_to_float32( !!!int64 );
float64 int64_to_float64( !!!int64 );
#ifdef FLOATX80
floatx80 int64_to_floatx80( !!!int64 );
#endif
#ifdef FLOAT128
float128 int64_to_float128( !!!int64 );
#endif

/*----------------------------------------------------------------------------
| Software IEEE single-precision conversion routines.
*----------------------------------------------------------------------------*/
!!!int32 float32_to_int32( float32 );
!!!int32 float32_to_int32_round_to_zero( float32 );
!!!int64 float32_to_int64( float32 );
!!!int64 float32_to_int64_round_to_zero( float32 );
float64 float32_to_float64( float32 );
#ifdef FLOATX80
floatx80 float32_to_floatx80( float32 );
#endif
#ifdef FLOAT128
float128 float32_to_float128( float32 );
#endif

/*----------------------------------------------------------------------------
| Software IEEE single-precision operations.
*----------------------------------------------------------------------------*/
float32 float32_round_to_int( float32 );
float32 float32_add( float32, float32 );
float32 float32_sub( float32, float32 );
float32 float32_mul( float32, float32 );
float32 float32_div( float32, float32 );
float32 float32_rem( float32, float32 );
float32 float32_sqrt( float32 );
!!!flag float32_eq( float32, float32 );
!!!flag float32_le( float32, float32 );
!!!flag float32_lt( float32, float32 );
!!!flag float32_eq_signaling( float32, float32 );
!!!flag float32_le_quiet( float32, float32 );
!!!flag float32_lt_quiet( float32, float32 );
!!!flag float32_is_signaling_nan( float32 );

/*----------------------------------------------------------------------------
| Software IEEE double-precision conversion routines.
*----------------------------------------------------------------------------*/
!!!int32 float64_to_int32( float64 );
!!!int32 float64_to_int32_round_to_zero( float64 );
!!!int64 float64_to_int64( float64 );
!!!int64 float64_to_int64_round_to_zero( float64 );
float32 float64_to_float32( float64 );
#ifdef FLOATX80
floatx80 float64_to_floatx80( float64 );
#endif
#ifdef FLOAT128
float128 float64_to_float128( float64 );
#endif

/*----------------------------------------------------------------------------
| Software IEEE double-precision operations.
*----------------------------------------------------------------------------*/
float64 float64_round_to_int( float64 );
float64 float64_add( float64, float64 );
float64 float64_sub( float64, float64 );
float64 float64_mul( float64, float64 );
float64 float64_div( float64, float64 );
float64 float64_rem( float64, float64 );
float64 float64_sqrt( float64 );
!!!flag float64_eq( float64, float64 );
!!!flag float64_le( float64, float64 );
!!!flag float64_lt( float64, float64 );
!!!flag float64_eq_signaling( float64, float64 );
!!!flag float64_le_quiet( float64, float64 );
!!!flag float64_lt_quiet( float64, float64 );
!!!flag float64_is_signaling_nan( float64 );

#ifdef FLOATX80

/*----------------------------------------------------------------------------
| Software IEEE double-extended-precision conversion routines.
*----------------------------------------------------------------------------*/
!!!int32 floatx80_to_int32( floatx80 );
!!!int32 floatx80_to_int32_round_to_zero( floatx80 );
!!!int64 floatx80_to_int64( floatx80 );
!!!int64 floatx80_to_int64_round_to_zero( floatx80 );
float32 floatx80_to_float32( floatx80 );
float64 floatx80_to_float64( floatx80 );
#ifdef FLOAT128
float128 floatx80_to_float128( floatx80 );
#endif

/*----------------------------------------------------------------------------
| Software IEEE double-extended-precision rounding precision.  Valid values
| are 32, 64, and 80.
*----------------------------------------------------------------------------*/
extern !!!int8 floatx80_rounding_precision;

/*----------------------------------------------------------------------------
| Software IEEE double-extended-precision operations.
*----------------------------------------------------------------------------*/
floatx80 floatx80_round_to_int( floatx80 );
floatx80 floatx80_add( floatx80, floatx80 );
floatx80 floatx80_sub( floatx80, floatx80 );
floatx80 floatx80_mul( floatx80, floatx80 );
floatx80 floatx80_div( floatx80, floatx80 );
floatx80 floatx80_rem( floatx80, floatx80 );
floatx80 floatx80_sqrt( floatx80 );
!!!flag floatx80_eq( floatx80, floatx80 );
!!!flag floatx80_le( floatx80, floatx80 );
!!!flag floatx80_lt( floatx80, floatx80 );
!!!flag floatx80_eq_signaling( floatx80, floatx80 );
!!!flag floatx80_le_quiet( floatx80, floatx80 );
!!!flag floatx80_lt_quiet( floatx80, floatx80 );
!!!flag floatx80_is_signaling_nan( floatx80 );

#endif

#ifdef FLOAT128

/*----------------------------------------------------------------------------
| Software IEEE quadruple-precision conversion routines.
*----------------------------------------------------------------------------*/
!!!int32 float128_to_int32( float128 );
!!!int32 float128_to_int32_round_to_zero( float128 );
!!!int64 float128_to_int64( float128 );
!!!int64 float128_to_int64_round_to_zero( float128 );
float32 float128_to_float32( float128 );
float64 float128_to_float64( float128 );
#ifdef FLOATX80
floatx80 float128_to_floatx80( float128 );
#endif

/*----------------------------------------------------------------------------
| Software IEEE quadruple-precision operations.
*----------------------------------------------------------------------------*/
float128 float128_round_to_int( float128 );
float128 float128_add( float128, float128 );
float128 float128_sub( float128, float128 );
float128 float128_mul( float128, float128 );
float128 float128_div( float128, float128 );
float128 float128_rem( float128, float128 );
float128 float128_sqrt( float128 );
!!!flag float128_eq( float128, float128 );
!!!flag float128_le( float128, float128 );
!!!flag float128_lt( float128, float128 );
!!!flag float128_eq_signaling( float128, float128 );
!!!flag float128_le_quiet( float128, float128 );
!!!flag float128_lt_quiet( float128, float128 );
!!!flag float128_is_signaling_nan( float128 );

#endif

