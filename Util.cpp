#include "Util.h"

bool isAdditionOverflow(unsigned long long* result, unsigned long long a, unsigned long long b)
{
    *result = a + b;
    if (a > 0 && b > 0 && *result < 0)
        return true;
    if (a < 0 && b < 0 && *result > 0)
        return true;
    return false;
}