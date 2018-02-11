#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

static float arithmetic_mean(float* data, int size);
static float mean_of_products(float* data1, float* data2, int size);
static float standard_deviation(float* data, int size);

//--------------------------------------------------------
// FUNCTION pearson_correlation
//--------------------------------------------------------
float pearson_correlation(float* X, float* Y, int size)
{
    float rho;

    // covariance
    float independent_mean = arithmetic_mean(X, size);
    float dependent_mean = arithmetic_mean(Y, size);
    float products_mean = mean_of_products(X, Y, size);
    float covariance = products_mean - (independent_mean * dependent_mean);

    // standard deviations of independent values
    float independent_standard_deviation = standard_deviation(X, size);

    // standard deviations of dependent values
    float dependent_standard_deviation = standard_deviation(Y, size);

    // Pearson Correlation Coefficient
    rho = covariance / (independent_standard_deviation * dependent_standard_deviation);

    return rho;
}

//--------------------------------------------------------
// FUNCTION arithmetic_mean
//--------------------------------------------------------
static float arithmetic_mean(float* data, int size)
{
    float total = 0;

    // note that incrementing total is done within the for loop
    for(int i = 0; i < size; total += data[i], i++);

    return total / size;
}

//--------------------------------------------------------
// FUNCTION mean_of_products
//--------------------------------------------------------
static float mean_of_products(float* data1, float* data2, int size)
{
    float total = 0;

    // note that incrementing total is done within the for loop
    for(int i = 0; i < size; total += (data1[i] * data2[i]), i++);

    return total / size;
}

//--------------------------------------------------------
// FUNCTION standard_deviation
//--------------------------------------------------------
static float standard_deviation(float* data, int size)
{
    float squares[size];

    for(int i = 0; i < size; i++)
    {
        squares[i] = pow(data[i], 2);
    }

    float mean_of_squares = arithmetic_mean(squares, size);
    float mean = arithmetic_mean(data, size);
    float square_of_mean = pow(mean, 2);
    float variance = mean_of_squares - square_of_mean;
    float std_dev = sqrt(variance);

    return std_dev;
}

int main(){
    float list_a[6] = {0.12890625, -0.005859375, 0.08203125, 0.048828125, 0.126953125, -0.047851563};
    float list_b[6] = {0.125976563, -0.013671875, 0.07421875, 0.043945313, 0.123046875, -0.053710938};
    float coef = pearson_correlation(list_a, list_b, 6);
    printf("%f\n", coef);
}