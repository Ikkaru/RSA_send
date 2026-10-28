# Pengolahan Citra
import numpy as np
from PIL import Image

class ImageProcessor:

    # Constructor
    def __init__(self, image_path):
        # Instance Attribute
        self._image_path = image_path
        self._total_bytes = 0
        self._original_shape = None
        self._raw_bytes = None

    # Method to conver images to array of bytes
    def to_bytes(self):
        # Load the image
        img = Image.open(self._image_path)

        # Convert to numpy array
        img_arr = np.array(img)
        self._original_shape = np.shape(img_arr)

        # Convert to bytes
        self._raw_bytes = img_arr.tobytes()
        self._total_bytes = len(self._raw_bytes)

        return self._raw_bytes

# Function to chunk the bytes
def chunk(data: bytes, n: int) -> list[bytes]:
    chunk_size = max(1, (n.bit_length() - 1) // 8)  # Calculate chunk size

    # Chunking
    chunks = []
    
    for i in range(0, len(data), chunk_size):
        block = data[i : i + chunk_size]
        chunks.append(block)
    return chunks


# Function to join chunks of bytes to raw bytes
def chunks_join(chunks: list[bytes]) -> bytes:
    raw_bytes = b""

    [item for sublist in chunks for item in sublist]
        




if __name__ == "__main__":
    a = ImageProcessor('./mbg.jpg').to_bytes()
    b = chunk(a, 65537)
    print(len(b))
    print(len(b[0]))


         
        

