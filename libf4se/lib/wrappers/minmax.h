#ifndef MINMAX_H
#define MINMAX_H

#pragma message("minmax.h is being processed")


#ifdef min
#undef min
#endif

#ifdef max
#undef max
#endif

#define min(a,b) (((a) < (b)) ? (a) : (b))
#define max(a,b) (((a) > (b)) ? (a) : (b))

#endif // MINMAX_H