#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <math.h>
#include "pearson.h"

static double standard_deviation(double* data, int size);

/**
 * returns pearson correlation coefficient given 2 lists of doubles
 * @param double* X, double* Y
 * @param int size
 * @return double
 */

// tested independently : works
// changed type from double to double to facilitate integration of the code
double pearson_correlation(double* X, double* Y, int size)
{
    double pearson;
    double tmp_X = 0, tmp_Y = 0, tot = 0;

    double EX;
    double EY;
    double EXY;
    double covariance;
    double X_deviation;
    double Y_deviation;

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

    return pearson;
}


static double standard_deviation(double* data, int size)
{
    double squares[size];
    double mean_of_squares;
    double mean;
    double square_of_mean;
    double variance;
    double res;
    double tmp = 0;

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

/*int main(){
    double list_a[6] = {0.12890625, -0.005859375, 0.08203125, 0.048828125, 0.126953125, -0.047851563};
    double list_b[6] = {0.125976563, -0.013671875, 0.07421875, 0.043945313, 0.123046875, -0.053710938};
    double coef = pearson_correlation(list_a, list_b, 6);
    printf("%f\n", coef);
}*/