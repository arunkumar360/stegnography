
from tkinter import *
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
import os
import zlib
import base64
import hashlib


class SteganographyApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Steganography App")
        self.root.geometry("700x700")
        self.root.resizable(False, False)
        self.root.config(bg="#f0f0f0")

        # Variables
        self.selected_image_path = ""
        self.message = ""
        self.password = ""
        self.encoded_image_path = ""

        # Main Frame
        self.main_frame = Frame(self.root, bg="#f0f0f0")
        self.main_frame.pack(expand=True, fill="both")

        # Title
        self.title_label = Label(self.main_frame, text="Steganography App", font=("Arial", 20, "bold"), bg="#f0f0f0")
        self.title_label.pack(pady=(20, 10))

        # Image Selection Frame
        self.image_frame = LabelFrame(self.main_frame, text="Select Image", font=("Arial", 12, "bold"), bg="#f0f0f0")
        self.image_frame.pack(pady=(0, 10), padx=10, fill="both")

        self.select_image_button = Button(self.image_frame, text="Select Image", font=("Arial", 12),
                                          command=self.select_image)
        self.select_image_button.pack(pady=(10, 20))

        # Message Entry Frame
        self.message_frame = LabelFrame(self.main_frame, text="Enter Message", font=("Arial", 12, "bold"), bg="#f0f0f0")
        self.message_frame.pack(pady=(0, 10), padx=10, fill="both")

        self.message_entry = Text(self.message_frame, font=("Arial", 12), height=5)
        self.message_entry.pack(pady=(10, 20))

        # Password Entry Frame
        self.password_frame = LabelFrame(self.main_frame, text="Enter Password (Optional)",
                                         font=("Arial", 12, "bold"), bg="#f0f0f0")
        self.password_frame.pack(pady=(0, 10), padx=10, fill="both")

        self.password_entry = Entry(self.password_frame, font=("Arial", 12), show="*")
        self.password_entry.pack(pady=(10, 20))

        # Buttons Frame
        self.buttons_frame = Frame(self.main_frame, bg="#f0f0f0")
        self.buttons_frame.pack(pady=(0, 20))

        self.encode_button = Button(self.buttons_frame, text="Encode", font=("Arial", 12), command=self.encode)
        self.encode_button.grid(row=0, column=0, padx=10)

        self.decode_button = Button(self.buttons_frame, text="Decode", font=("Arial", 12), command=self.decode)
        self.decode_button.grid(row=0, column=1, padx=10)

        self.clear_button = Button(self.buttons_frame, text="Clear", font=("Arial", 12), command=self.clear_fields)
        self.clear_button.grid(row=0, column=2, padx=10)

    def select_image(self):
        self.selected_image_path = filedialog.askopenfilename(title="Select Image",
                                                              filetypes=(("PNG files", "*.png"),
                                                                         ("JPEG files", "*.jpg;*.jpeg"),
                                                                         ("All files", "*.*")))
        if self.selected_image_path:
            self.preview_image()

    def preview_image(self):
        image = Image.open(self.selected_image_path)
        image.thumbnail((200, 200))
        photo = ImageTk.PhotoImage(image)

        if hasattr(self, "image_label"):
            self.image_label.destroy()

        self.image_label = Label(self.image_frame, image=photo, bg="#f0f0f0")
        self.image_label.image = photo
        self.image_label.pack(pady=(0, 10))

    def encode(self):
        self.message = self.message_entry.get("1.0", "end-1c").strip()
        self.password = self.password_entry.get().strip()

        if not self.selected_image_path or not self.message:
            messagebox.showerror("Error", "Please select an image and enter a message.")
            return

        # Encrypt message if password is provided
        if self.password:
            self.message = self.encrypt_message(self.message, self.password)

        # Embed message into image
        try:
            with open(self.selected_image_path, "rb") as img_file:
                img_data = img_file.read()

            encoded_img_data = self.encode_message_into_image(img_data, self.message)

            encoded_image_path = filedialog.asksaveasfilename(defaultextension=".png",
                                                              filetypes=(("PNG files", "*.png"),))
            if encoded_image_path:
                with open(encoded_image_path, "wb") as encoded_img_file:
                    encoded_img_file.write(encoded_img_data)

                messagebox.showinfo("Success", "Message encoded successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def encode_message_into_image(self, img_data, message):
        # Compress message
        compressed_message = zlib.compress(message.encode())

        # Base64 encode compressed message
        encoded_message = base64.b64encode(compressed_message).decode()

        # Calculate message hash
        message_hash = hashlib.sha256(message.encode()).hexdigest()

        # Embed message length, hash, and encoded message into image
        separator = b"|!|"
        encoded_img_data = img_data + separator + str(len(encoded_message)).encode() + separator \
                           + message_hash.encode() + separator + encoded_message.encode()

        return encoded_img_data

    def encrypt_message(self, message, password):
        # Add encryption logic here (e.g., AES encryption)
        encrypted_message = message + " (encrypted)"
        return encrypted_message

    def decode(self):
        self.selected_image_path = filedialog.askopenfilename(title="Select Image",
                                                              filetypes=(("PNG files", "*.png"),))

        if self.selected_image_path:
            try:
                with open(self.selected_image_path, "rb") as img_file:
                    img_data = img_file.read()

                decoded_message = self.decode_message_from_image(img_data)

                # Decrypt message if password is provided
                if self.password:
                    decoded_message = self.decrypt_message(decoded_message, self.password)

                self.message_entry.delete("1.0", "end")
                self.message_entry.insert("1.0", decoded_message)
            except Exception as e:
                messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def decode_message_from_image(self, img_data):
        separator = b"|!|"

        # Split image data to extract encoded message, length, and hash
        img_data_parts = img_data.split(separator)
        encoded_message_len = int(img_data_parts[-3])
        message_hash = img_data_parts[-2]
        encoded_message = img_data_parts[-1]

        # Extract encoded message
       

        encoded_message = encoded_message[:encoded_message_len]

        # Base64 decode and decompress message
        compressed_message = base64.b64decode(encoded_message)
        message = zlib.decompress(compressed_message).decode()

        # Verify message integrity using hash
        if hashlib.sha256(message.encode()).hexdigest() != message_hash.decode():
            raise ValueError("Message integrity check failed.")

        return message

    def decrypt_message(self, message, password):
        # Add decryption logic here (e.g., AES decryption)
        decrypted_message = message.replace(" (encrypted)", "")
        return decrypted_message

    def clear_fields(self):
        self.selected_image_path = ""
        self.message_entry.delete("1.0", "end")
        self.password_entry.delete(0, "end")
        if hasattr(self, "image_label"):
            self.image_label.destroy()


if __name__ == "__main__":
    root = Tk()
    app = SteganographyApp(root)
    root.mainloop()
