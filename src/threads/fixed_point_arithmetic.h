//
// Created by Ana Raicu on 20.10.2021.
//

#ifndef PINTOS_15_FIXED_POINT_ARITHMETIC_H
#define PINTOS_15_FIXED_POINT_ARITHMETIC_H

#include <stdio.h>
#include <debug.h>
#include <stddef.h>
#include <random.h>

#define P 17
#define Q 14
#define F (1 << Q)

typedef int32_t Fixed_point;

#define FP(X) (X * F)

#define FP_TO_INT_TRUNCATE(X) (X / F)

#define FP_TO_INT_NEAREST(X) (X >= 0 ? (X + F / 2) / F : (X - F / 2) / F)

#define FP_ADD(X, Y) (X + Y)

/*
 * Subtracts y from x
 * */
#define FP_SUBTRACT(X, Y) (X - Y)

#define FP_ADD_I(X, Y) (X + FP(Y))

#define FP_SUBTRACT_I(X, Y) (X - FP(Y))

#define FP_MULTIPLY(X, Y) (((int64_t)X) * Y / F)

#define FP_MULTIPLY_I(X, N) (X * N)

#define FP_DIVIDE(X, Y) (((int64_t)X) * F / Y)

#define FP_DIVIDE_I(X, N) (X / N)

#endif //PINTOS_15_FIXED_POINT_ARITHMETIC_H
