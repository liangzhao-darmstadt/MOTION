/* Neural Network according to Figure 12 of MiniONN 
	Assumes image to be square, assume window size to be odd
*/
#include <stdio.h>
#include <string.h>

typedef unsigned DT;

void DT_memset(DT* OUTPUT_res, int len, DT val) {
	for(int i = 0; i < len; i++) {
		OUTPUT_res[i] = val;
	}
}

DT relu(DT val) {
	if(val>0) {
		return val;
	} else {
		return 0;
	}
}
void relu_map(DT *in, DT *OUTPUT_res, unsigned len) {
	for(int i = 0; i < len; i++) {
		OUTPUT_res[i] = relu(in[i]);
	}
}

void decomposed_relu(DT *in, DT *OUTPUT_res, unsigned len_outer, unsigned len_inner) {
	DT copy[len_inner];
	DT im_res[len_inner];
	for(int i = 0; i < len_outer; i++) {
		memcpy(copy, in+i*len_inner, len_inner*sizeof(DT));
		relu_map(in, im_res, len_inner);
		memcpy(OUTPUT_res + i*len_inner, im_res, len_inner*sizeof(DT));
	}
}


void max_pooling(DT *vals, DT *OUTPUT_res, unsigned cols, unsigned rows) {
	unsigned rows_res = rows / 2;
	unsigned cols_res = cols / 2;
	for(unsigned i = 0; i < rows_res; i++) {
		for(unsigned j = 0; j < cols_res; j++) {
			unsigned x = j * 2;
			unsigned y = i * 2;
			DT max = vals[y*cols + x];
			if(vals[y*cols + x + 1] > max) {
				max = vals[y*cols + x + 1];
			}
			if(vals[(y + 1) *cols + x] > max) {
				max = vals[(y + 1) * cols + x];
			} 
			if(vals[(y + 1) *cols + x + 1] > max) {
				max = vals[(y + 1) * cols + x + 1];
			} 
			OUTPUT_res[i * cols_res + j] = max;
		}
	}
}

void max_pooling_outputs(DT *vals, DT *OUTPUT_res, unsigned outputs, unsigned cols, unsigned rows) {
	for(int o = 0; o < outputs; o++) {
		unsigned size = cols*rows; 
		DT input_layer[size]; // We copy data, because compiler is unable to slice array efficiently
		memcpy(input_layer, vals+o*size, size * sizeof(DT));
		unsigned output_size = cols/2*rows/2;
		DT res_layer[output_size];
		max_pooling(input_layer, res_layer, cols, rows);
		memcpy(OUTPUT_res+o*output_size, res_layer, output_size * sizeof(DT));
	}
}



DT mmulT_unrolled_inner(DT* a, DT* b, unsigned common) { 
	DT sum = 0;
	for(unsigned k = 0; k < common; k++) {
		sum += a[k] * b[k];
	}
	return sum;
}


void mmulT_unrolled(DT* a, DT* b, DT *OUTPUT_res, unsigned cols_a, unsigned cols_b, unsigned common) {
	for(unsigned i = 0; i < cols_a; i++) {
		DT aRow[common];
		memcpy(aRow, a+i*common, common*sizeof(DT));
		for(unsigned j = 0; j < cols_b; j++) {
			DT bRow[common];
			memcpy(bRow, b+j*common, common*sizeof(DT));
			OUTPUT_res[i*cols_b+j] = mmulT_unrolled_inner(aRow, bRow, common);
		}
	}
}




void convolution_naive_outputs(DT *image, DT* kernels, DT* OUTPUT_layer, unsigned image_width, unsigned window_size, unsigned output_size, unsigned stride, unsigned conv_width) {	
	unsigned kernel_size = window_size*window_size;
	for(unsigned o = 0; o < output_size; o++) {
		memcpy(OUTPUT_layer + o*(conv_width*conv_width), image, conv_width*conv_width * sizeof(DT));
	}
}


// Parameters taken from the paper
#define IMAGE_WIDTH 28
#define WINDOW_WIDTH 5
#define STRIDE 1
#define OUTPUT_CHANNELS 16

#define IMAGE_CROP (IMAGE_WIDTH - WINDOW_WIDTH + 1) // 28-5+1 = 24
#define SIZE_CONVOLUTION_1 (IMAGE_CROP * IMAGE_CROP) //Intermediate size (24^2 = 576
#define MAX_POOLING_WIDTH_1 (IMAGE_CROP / 2)//24/2=12

#define IMAGE_WIDTH_2 MAX_POOLING_WIDTH_1
#define MAX_POOLING_SIZE_1 (OUTPUT_CHANNELS*MAX_POOLING_WIDTH_1 * MAX_POOLING_WIDTH_1) // 16*12*12
#define IMAGE_CROP_2 (MAX_POOLING_WIDTH_1-WINDOW_WIDTH +1) // 12-5+1 = 8
#define SIZE_KERNELS_2 (WINDOW_WIDTH*WINDOW_WIDTH)  // 5*5 = 25 
#define SIZE_ALL_KERNELS_2 (SIZE_KERNELS_2 * OUTPUT_CHANNELS) // 16 * 25

#define SIZE_CONVOLUTION_2 (IMAGE_CROP_2*IMAGE_CROP_2) // 8*8 = 64
#define SIZE_RELU_2 OUTPUT_CHANNELS * IMAGE_CROP_2 * IMAGE_CROP_2 // 16 * 64

#define MAX_POOLING_WIDTH_2 (IMAGE_CROP_2 / 2) // 8/2 = 4
#define MAX_POOLING_SIZE_2 (OUTPUT_CHANNELS * MAX_POOLING_WIDTH_2 * MAX_POOLING_WIDTH_2)

#define FULLY_CONNECTED_WIDTH 100 // (7, 9)
#define FINAL_OUTPUT_CHANNELS 10

typedef struct
{
	DT image[IMAGE_WIDTH * IMAGE_WIDTH];
} InputA;


typedef struct
{
	DT kernelsL1[OUTPUT_CHANNELS * WINDOW_WIDTH * WINDOW_WIDTH]; // (1)
	DT kernelsL2[OUTPUT_CHANNELS * SIZE_KERNELS_2]; // (16 * 
	DT kernelsFC1[FULLY_CONNECTED_WIDTH * MAX_POOLING_SIZE_2]; // (16 * 4 * 4) * 100 = 256 * 100
	DT kernelsFC2[FINAL_OUTPUT_CHANNELS * FULLY_CONNECTED_WIDTH]; // 100 * 10
} InputB;

typedef struct
{
	DT final_layer[FINAL_OUTPUT_CHANNELS];
	//DT final_layer[MAX_POOLING_SIZE_1];
} Output;

void sum(DT *OUTPUT_agg, DT* agg, DT *add, int len) {
	for(int i = 0; i < len; i++) {
		OUTPUT_agg[i] = agg[i] + add[i];
	}
}

Output mpc_main(InputA INPUT_A, InputB INPUT_B)
{
	DT convolution_layer[OUTPUT_CHANNELS * SIZE_CONVOLUTION_1];
	DT convolution_relu[OUTPUT_CHANNELS * SIZE_CONVOLUTION_1];

	Output output;

	// Convolution (1)
	//, DT* kernels, DT* OUTPUT_layer, unsigned image_width, unsigned window_size, unsigned output_size, unsigned stride, unsigned conv_width) {	
	convolution_naive_outputs(INPUT_A.image, INPUT_B.kernelsL1, convolution_layer, IMAGE_WIDTH, WINDOW_WIDTH, OUTPUT_CHANNELS, STRIDE, IMAGE_CROP);
	
	// Relu (2)
	//for(unsigned i = 0; i < OUTPUT_CHANNELS * SIZE_CONVOLUTION_1; i++) {
	decomposed_relu(convolution_layer, convolution_relu, OUTPUT_CHANNELS, SIZE_CONVOLUTION_1);

	// Max pooling (3)
	DT pooling_layer[MAX_POOLING_SIZE_1]; // Size is 16 * 12 *12
	max_pooling_outputs(convolution_relu, pooling_layer, OUTPUT_CHANNELS, IMAGE_CROP, IMAGE_CROP);	
	
	
	DT convolution_layer_2[OUTPUT_CHANNELS * SIZE_CONVOLUTION_2]; // 16 * (8*8)
	DT convolution_relu_2[OUTPUT_CHANNELS * SIZE_CONVOLUTION_2]; // 16 * (8*8)
	DT_memset(convolution_layer_2, OUTPUT_CHANNELS * SIZE_CONVOLUTION_2, 0);
	for(unsigned o = 0; o < OUTPUT_CHANNELS; o++) { // Accumulate convolutions
		DT convolution_layer_tmp[OUTPUT_CHANNELS * SIZE_CONVOLUTION_2]; // 16 * (8*8)
		DT convolution_layer_tmp_2[OUTPUT_CHANNELS * SIZE_CONVOLUTION_2]; // 16 * (8*8)
		DT image[IMAGE_WIDTH_2*IMAGE_WIDTH_2]; // 12*12=144
		DT kernels[SIZE_ALL_KERNELS_2];
		memcpy(kernels, INPUT_B.kernelsL2, SIZE_ALL_KERNELS_2*sizeof(DT));
		memcpy(image, pooling_layer+o*IMAGE_WIDTH_2*IMAGE_WIDTH_2, IMAGE_WIDTH_2*IMAGE_WIDTH_2*sizeof(DT));
		convolution_naive_outputs(image, kernels, convolution_layer_tmp, IMAGE_WIDTH_2, WINDOW_WIDTH, OUTPUT_CHANNELS, STRIDE, IMAGE_CROP_2);
		sum(convolution_layer_tmp_2, convolution_layer_2, convolution_layer_tmp, OUTPUT_CHANNELS * SIZE_CONVOLUTION_2);
		memcpy(convolution_layer_2, convolution_layer_tmp_2, OUTPUT_CHANNELS * SIZE_CONVOLUTION_2);
	}
	
	decomposed_relu(convolution_layer_2, convolution_relu_2, OUTPUT_CHANNELS, SIZE_CONVOLUTION_2);
	
	
	// Max pooling (6)
	DT pooling_layer_2[MAX_POOLING_SIZE_2]; // Size is 16 * 4 * 4
	max_pooling_outputs(convolution_relu_2, pooling_layer_2, OUTPUT_CHANNELS, IMAGE_CROP_2, IMAGE_CROP_2);	
	
	// FC (7)
	DT fc_layer[FULLY_CONNECTED_WIDTH];
	//DT_memset(pooling_layer_2, MAX_POOLING_SIZE_2, 2);
	mmulT_unrolled(INPUT_B.kernelsFC1, pooling_layer_2, fc_layer, FULLY_CONNECTED_WIDTH, 1, MAX_POOLING_SIZE_2);
	
	// RELU (8)
	DT fc_relu[FULLY_CONNECTED_WIDTH];
	decomposed_relu(fc_layer, fc_relu, FULLY_CONNECTED_WIDTH, 1);
	
	// Temporary output
	//	memcpy(output.final_layer, pooling_layer_2, FINAL_OUTPUT_CHANNELS*sizeof(DT));

	mmulT_unrolled(INPUT_B.kernelsFC2, fc_layer, output.final_layer, FINAL_OUTPUT_CHANNELS, 1, FULLY_CONNECTED_WIDTH);

	return output;
}

/*void main() {
	InputB testB;
	DT_memset(testB.kernelsL1, OUTPUT_CHANNELS * WINDOW_WIDTH * WINDOW_WIDTH, 1); // (1)
	DT_memset(testB.kernelsL2, OUTPUT_CHANNELS * SIZE_KERNELS_2, 1); 
	DT_memset(testB.kernelsFC1, FC_COLS_1 * FULLY_CONNECTED_WIDTH, 3);
	DT_memset(testB.kernelsFC2, FINAL_OUTPUT_CHANNELS * FULLY_CONNECTED_WIDTH, 2); 	

	InputA testA;
	DT_memset(testA.image,1, IMAGE_WIDTH *IMAGE_WIDTH);
	
	Output res = mpc_main(testA, testB);
	printf("Result:");
	for(unsigned i = 0; i < FINAL_OUTPUT_CHANNELS; i++) {
		printf("%d", res.final_layer[i]);
	}
}*/
