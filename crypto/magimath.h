// Copyright (c) 2014 The Magi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef MAGI_MATH_H
#define MAGI_MATH_H

#include <math.h>

#ifdef __cplusplus
extern "C" {
#endif

uint32_t sw_(int nnounce, int divs);

#ifdef __cplusplus
}
#endif


inline double exp_n(double xt)
{
	double p1 = -700.0, p3 = -0.8e-8, p4 = 0.8e-8, p6 = 700.0;
	if(xt < p1)
		return 0;
	else if(xt > p6)
		return 1e200;
	else if(xt > p3 && xt < p4)
		return (1.0 + xt);
	else
		return exp(xt);
}

// 1 / (1 + exp(x1-x2))
inline double exp_n2(double x1, double x2)
{
	double p1 = -700., p2 = -37., p3 = -0.8e-8, p4 = 0.8e-8, p5 = 37., p6 = 700.;
	double xt = x1 - x2;
	if (xt < p1+1.e-200)
		return 1.;
	else if (xt > p1 && xt < p2 + 1.e-200)
		return ( 1. - exp(xt) );
	else if (xt > p2 && xt < p3 + 1.e-200)
		return ( 1. / (1. + exp(xt)) );
	else if (xt > p3 && xt < p4)
		return ( 1. / (2. + xt) );
	else if (xt > p4 - 1.e-200 && xt < p5)
		return ( exp(-xt) / (1. + exp(-xt)) );
	else if (xt > p5 - 1.e-200 && xt < p6)
		return ( exp(-xt) );
	else //if (xt > p6 - 1.e-200)
		return 0.;
}

#endif
