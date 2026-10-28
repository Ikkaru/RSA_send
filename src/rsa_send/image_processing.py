# Pengolahan Citra
import numpy as np
from PIL import Image


class ImageProcessor:

  def __init__(self, image_path: str):
    self._image_path = image_path
    self._original_shape = None
    self._dtype = None

  def to_bytes(self) -> tuple[bytes, tuple, str]:
    """Membaca gambar dan mengembalikan raw bytes, dimensi (shape), serta tipe data (dtype)."""
    img = Image.open(self._image_path)
    img_arr = np.array(img)

    self._original_shape = img_arr.shape
    self._dtype = str(img_arr.dtype)

    return img_arr.tobytes(), self._original_shape, self._dtype

  @staticmethod
  def to_image(
      raw_bytes: bytes, shape: tuple, dtype: str = "uint8"
  ) -> Image.Image:
    """Merekonstruksi raw bytes kembali menjadi objek PIL Image di sisi Server."""
    img_arr = np.frombuffer(raw_bytes, dtype=dtype).reshape(shape)
    return Image.fromarray(img_arr)


def chunk(data: bytes, chunk_size: int = 16384) -> list[bytes]:
  """Memotong data bytes menjadi list of chunks (default 16 KiB)."""
  return [
      data[i : i + chunk_size] for i in range(0, len(data), chunk_size)
  ]


def chunks_join(chunks: list[bytes]) -> bytes:
  """Menggabungkan kembali list of chunks menjadi bytes utuh."""
  return b"".join(chunks)


if __name__ == "__main__":
  processor = ImageProcessor("./test/mbg.jpg")
  raw_bytes, shape, dtype = processor.to_bytes()

  # Uji pemotongan & penggabungan
  chunks_list = chunk(raw_bytes, 16384)
  print(f"Jumlah chunk        : {len(chunks_list)}")
  print(f"Ukuran chunk awal   : {len(chunks_list[0])} bytes")

  reconstructed_bytes = chunks_join(chunks_list)
  img = ImageProcessor.to_image(reconstructed_bytes, shape, dtype)
  print(f"Ukuran gambar hasil : {img.size}")