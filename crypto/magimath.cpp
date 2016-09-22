// Copyright (c) 2014 The Magi developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <iostream>
#include <cfloat>
#include <limits>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "magimath.h"

#define EPS1 (std::numeric_limits<double>::epsilon())
#define EPS2 3.0e-11

static void gauleg(double x1, double x2, double x[], double w[], const int n)
{
	int m,j,i;
	double z1, z, xm, xl, pp, p3, p2, p1;
	m=(n+1)/2;
	xm=0.5*(x2+x1);
	xl=0.5*(x2-x1);
	for (i=1;i<=m;i++) {
		z=cos(3.141592654*(i-0.25)/(n+0.5));
		do {
			p1=1.0;
			p2=0.0;
			for (j=1;j<=n;j++) {
				p3=p2;
				p2=p1;
				p1=((2.0*j-1.0)*z*p2-(j-1.0)*p3)/j;
			}
			pp=n*(z*p1-p2)/(z*z-1.0);
			z1=z;
			z=z1-p1/pp;
		} while (fabs(z-z1) > EPS2);
		x[i]=xm-xl*z;
		x[n+1-i]=xm+xl*z;
		w[i]=2.0*xl/((1.0-z*z)*pp*pp);
		w[n+1-i]=w[i];
	}
}

static double GaussianQuad_N(double func(const double), const double a2, const double b2, const int NptGQ)
{
	double s=0.0;
#ifdef _MSC_VER
#define SW_DIVS 23
	double x[SW_DIVS+1], w[SW_DIVS+1];
#else
	double x[NptGQ+1], w[NptGQ+1];
#endif

	gauleg(a2, b2, x, w, NptGQ);

	for (int j=1; j<=NptGQ; j++) {
		s += w[j]*func(x[j]);
	}

	return s;
}

static double swit_(double wvnmb)
{
	return pow( (5.55243*(exp_n(-0.3*wvnmb/15.762) - exp_n(-0.6*wvnmb/15.762)))*wvnmb, 0.5)
		/ 1034.66 * pow(sin(wvnmb/65.), 2.);
}

uint32_t sw_(int nnounce, int divs)
{
	double wmax = ((sqrt((double)(nnounce))*(1.+EPS1))/450+100);
	return ((uint32_t)(GaussianQuad_N(swit_, 0., wmax, divs)*(1.+EPS1)*1.e6));
}
