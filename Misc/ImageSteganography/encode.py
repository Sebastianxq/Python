from PIL import Image

message = "Hello" #msg to encrypt #
data = ''.join(format(ord(i), 'b') for i in message) #conver string to binary#

i=0
#counts go to 12
print(len(data))
with Image.open("test1.png") as img:
	width, height = img.size #img constraints#
	for x in range(0,width):
		for y in range(0,height):
			#print(c)
			pixel = list(img.getpixel((x, y)))
			#print("this is pixel", pixel)
			for n in range(0,3): #r,g,b
				if (i<len(data)):
					pixel[n] = pixel[n] & ~1 | int(data[i])
					i+=1
					img.putpixel((x,y), tuple(pixel))
		img.save("secret_image.png", "PNG")

print("Done")