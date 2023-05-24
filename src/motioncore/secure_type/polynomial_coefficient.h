#pragma once

// coefficient of tanh x in interval: [2,inf], [1,2), [0.5,1), [0.25,0.5), [0,0.25), [-0.5,0),
// [-2,-0.5), [-inf,-2)

static const double tanh_x_pow0_coe[8] = {
    1, -0.04236632706950516, -0.03677167948406834, -0.002559789038352855, 0, 0, 0.06216275992789025,
    -1};

static const double tanh_x_pow1_coe[8] = {0,
                                          1.278053367576582,
                                          1.2156478693237276,
                                          1.0281949849652727,
                                          1.0001870798484163,
                                          1.0026428849947004,
                                          1.3203287354435673,
                                          0};
static const double tanh_x_pow2_coe[8] = {0,
                                          -0.560757562100663,
                                          -0.45419874945839095,
                                          -0.10856724883910353,
                                          -0.0043755733038300815,
                                          0.03112890845080873,
                                          0.5901781419404275,
                                          0};
static const double tanh_x_pow3_coe[8] = {0,
                                          0.08666467754935131,
                                          0.03691671557449657,
                                          -0.17822987179598235,
                                          -0.3106965905219567,
                                          -0.25137646499710636,
                                          0.09328067960978532,
                                          0};

static const double tanh_x_app_interval_upper_bound[8] = {
    std::numeric_limits<double>::max(), 2, 1, 0.5, 0.25, 0, -0.5, -2};

static const double tanh_x_app_interval_lower_bound[8] = {
    2, 1, 0.5, 0.25, 0, -0.5, -2, std::numeric_limits<double>::min()};

// template <typename FixedPointType>
// FixedPointType tanh_x(const FixedPointType& x) {
//   std::size_t num_of_interval = 8;

//   std::vector<bool> interval_identifier_vector(num_of_interval);

//   for (std::size_t i = 0; i < num_of_interval; ++i) {
//     if (tanh_x_app_interval_upper_bound[i] == std::numeric_limits<T>::max()) {
//       // x >= lower_bound[i]
//       bool interval_check_tmp =
//           (x > tanh_x_app_interval_lower_bound[i]) & (x == tanh_x_app_interval_lower_bound[i]);
//       interval_identifier_vector.emplace_back(interval_check_tmp);
//     }

//     // lower bound is -inf
//     else if (tanh_x_app_interval_lower_bound[i] == std::numeric_limits<T>::min()) {
//       // x < upper_bound[i]
//       bool interval_check_tmp = (x < tanh_x_app_interval_upper_bound[i]);
//       interval_identifier_vector.emplace_back(interval_check_tmp);
//     }

//     // both upper bound and lower bound exist
//     // lower_bound[i] <= x < upper_bound[i]
//     else {
//       bool interval_check_tmp = (x < tanh_x_app_interval_upper_bound[i]) &
//                                 (x > tanh_x_app_interval_lower_bound[i]) &
//                                 (x == tanh_x_app_interval_lower_bound[i]);
//       interval_identifier_vector.emplace_back(interval_check_tmp);
//     }
//   }






// }
