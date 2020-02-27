from PIL import Image

def BinaryToDecimal(binary):
	#use int function to convert to string
	string = int(binary, 2)
	return string

extracted_bin = []

with Image.open("secret_image.png") as img:
	width, height = img.size
	byte = []
	for x in range(0, width):
		for y in range(0, height):
			pixel = list(img.getpixel((x,y)))
			for n in range(0,3):
				extracted_bin.append(pixel[n]&1) #reads LSB ??

		bin_data = ''.join([str(x) for x in extracted_bin])

str_data = ' '
for i in range(0, len(bin_data), 7):

	temp_data = bin_data[i:i + 7]
	decimal_data = BinaryToDecimal(temp_data)
	str_data = str_data + chr(decimal_data)

print ("The bin value after str conversion is:", str_data)