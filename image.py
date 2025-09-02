import numpy as np
from skimage.io import imread
from PIL import Image
import sys
np.set_printoptions(threshold=sys.maxsize)
im = imread("image.png")
a = np.asarray(im)[:,:,0]
img = np.resize(a, (20, 20))
img = Image.fromarray(img)
img.show()

print(np.asarray(img))