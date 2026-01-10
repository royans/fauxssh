# Risk Model v1 - Theano Implementation
# Author: bcooper
# Date: 2016-08-10

import theano
import theano.tensor as T
import numpy as np

print("Loading Risk Model v1.0...")
print("Using GPU: Tesla K80 (Device 0)")

# Placeholder for ancient code
x = T.dmatrix('x')
s = 1 / (1 + T.exp(-x))
logistic = theano.function([x], s)

data = np.random.randn(1000, 1000)
print("Running inference on batch size 1000...")
res = logistic(data)
print("Done.")
