import numpy
from ila import *
from skimage.io import imread
import sys
#from PIL import Image

numpy.set_printoptions(threshold=sys.maxsize)
im = imread("./artifact_tests/image.png")
a = numpy.asarray(im)[:,:,0]
a = np.resize(a, (20, 20))
img = '(' + str(a)[1:-1] +')'
filter = "([9 3 2 2 1 5 6 3 0 7 7 3 1 2 5 6 2 6 5 8] [0 1 1 0 7 9 1 4 2 0 5 0 8 4 4 2 7 7 0 7] [0 0 1 2 2 0 9 1 3 6 5 2 6 4 3 4 0 7 1 9] [0 0 0 5 0 4 7 1 5 3 4 4 5 7 7 9 7 4 7 3] [0 0 0 0 3 4 1 2 8 9 3 4 4 4 0 5 5 6 9 5] [0 0 0 0 0 9 6 8 9 9 0 8 7 7 5 7 8 6 2 4] [0 0 0 0 0 0 1 7 5 8 6 5 1 0 5 2 3 0 1 5] [0 0 0 0 0 0 0 5 2 6 9 1 1 0 5 5 0 9 7 5] [0 0 0 0 0 0 0 0 7 3 3 4 2 8 5 4 5 7 7 9] [0 0 0 0 0 0 0 0 0 2 2 7 5 9 3 9 4 8 6 5] [0 0 0 0 0 0 0 0 0 0 4 1 1 1 5 5 9 3 8 9] [0 0 0 0 0 0 0 0 0 0 0 1 9 3 2 4 4 5 1 2] [0 0 0 0 0 0 0 0 0 0 0 0 2 4 2 7 1 1 9 9] [0 0 0 0 0 0 0 0 0 0 0 0 0 9 4 3 6 2 2 2] [0 0 0 0 0 0 0 0 0 0 0 0 0 0 5 8 0 9 6 7] [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 8 0 2 5 7] [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 7 5 6 9] [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 1 6 3] [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 9 1] [0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 6])"

with open("image_filter.ila", "w") as f:
    f.write ('a : matrix cipher 20 20;\nx : matrix cipher 20 20;\ny : matrix cipher 20 20\n\na := minit '+img+';\nx := minit '+filter+';\ny := (a $ x)')
    f.close()


(typecheck, outputs, logq) = ila(1, 1, "image_filter.ila", 10)
print(outputs['y'])
#img = Image.fromarray(outputs['y'])
#img.show()
