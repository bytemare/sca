#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <math.h>

static float arithmetic_mean(float* data, int size);
static float mean_of_products(float* data1, float* data2, int size);
static float standard_deviation(float* data, int size);

/**
 * returns pearson correlation coefficient given 2 lists of floats
 * @param float* X, float* Y
 * @param int size
 * @return float
 */
float pearson_correlation(float* X, float* Y, int size)
{
    float pearson;
    float tmp_X = 0, tmp_Y = 0, tot = 0;

    float EX;
    float EY;
    float EXY;
    float covariance;
    float X_deviation;
    float Y_deviation;

    for(int i = 0; i < size; i++){
        tmp_X += X[i];
        tmp_Y += Y[i];
    }
    EX = tmp_X / size;
    EY = tmp_Y / size;

    for(int i = 0; i < size; i++){
        tot += (X[i] * Y[i]);
    }

    EXY = tot / size;

    covariance = EXY - (EX * EY);

    // standard deviations of independent values
    X_deviation = standard_deviation(X, size);

    // standard deviations of dependent values
    Y_deviation = standard_deviation(Y, size);

    // Pearson Correlation Coefficient
    pearson = covariance / (X_deviation * Y_deviation);

    printf("EX %f\nEY %f\nEXY %f\ncov %f\nX dev %f\nY dev %f\n", EX, EY, EXY, covariance, X_deviation, Y_deviation);

    return pearson;
}


static float standard_deviation(float* data, int size)
{
    float squares[size];
    float mean_of_squares;
    float mean;
    float square_of_mean;
    float variance;
    float res;
    float tmp = 0;

    for(int i = 0; i < size; i++)
    {
        squares[i] = pow(data[i], 2);
        tmp += data[i];
    }
    mean = tmp / size;
    square_of_mean = pow(mean, 2);

    tmp = 0;

    for(int i = 0; i < size; i++)
    {
        tmp += squares[i] = pow(data[i], 2);
    }
    mean_of_squares = tmp / size;

    variance = mean_of_squares - square_of_mean;
    res = sqrt(variance);

    return res;
}

int main(){
    float list_a[6] = {0.12890625, -0.005859375, 0.08203125, 0.048828125, 0.126953125, -0.047851563};
    float list_b[6] = {0.125976563, -0.013671875, 0.07421875, 0.043945313, 0.123046875, -0.053710938};
    float coef = pearson_correlation(list_a, list_b, 6);
    printf("%f\n", coef);
}