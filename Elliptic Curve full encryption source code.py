import collections
import hashlib
import random
import binascii
from Crypto.Cipher import AES
import Padding
from tkinter import *
import tkinter.font as font
from tkinter import messagebox
from tkinter.filedialog import askopenfile
import PyPDF2

EllipticCurve = collections.namedtuple('EllipticCurve', 'name p a b g n h')
# Field characteristic
curve = EllipticCurve(
    'sec256k1',
    # our prime number
    p=0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f,
    # Curve coefficients.
    a=0,
    b=7,
    # Base point.
    g=(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
       0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8),
    # Subgroup order.
    n=0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
    # Subgroup cofactor.
    h=1,
)


# Modular arithmetic
def inverse_mod(k, p):
    # mod inverse is the invented elliptic curve division
    """Returns the inverse of k modulo p.
    This function returns the only integer x such that (x * k) % p == 1.
    k must be non-zero and p must be a prime.
    """
    if k == 0:
        raise ZeroDivisionError('division by zero')

    if k < 0:
        # k ** -1 = p - (-k) ** -1  (mod p)
        return p - inverse_mod(-k, p)

    # Extended Euclidean algorithm.
    s, old_s = 0, 1
    t, old_t = 1, 0
    r, old_r = p, k

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s
        old_t, t = t, old_t - quotient * t

    gcd, x, y = old_r, old_s, old_t

    assert gcd == 1
    assert (k * x) % p == 1

    return x % p


# Functions that work on curve points
def point_neg(point):
    """Returns -point."""

    if point is None:
        # -0 = 0
        return None

    x, y = point
    result = (x, -y % curve.p)

    return result


def point_add(point1, point2):
    """Returns the result of point1 + point2 according to the group law."""

    if point1 is None:
        # 0 + point2 = point2
        return point2
    if point2 is None:
        # point1 + 0 = point1
        return point1

    x1, y1 = point1
    x2, y2 = point2

    if x1 == x2 and y1 != y2:
        # point1 + (-point1) = 0
        return None

    if x1 == x2:
        # This is the case point1 == point2.
        m = (3 * x1 * x1 + curve.a) * inverse_mod(2 * y1, curve.p)
    else:
        # This is the case point1 != point2.
        m = (y1 - y2) * inverse_mod(x1 - x2, curve.p)

    x3 = m * m - x1 - x2
    y3 = y1 + m * (x3 - x1)
    result = (x3 % curve.p, -y3 % curve.p)

    return result


def scalar_mult(k, point):
    """Scalar Multiplication using the double and point_add algorithm."""

    if k % curve.n == 0 or point is None:
        return None

    if k < 0:
        # k * point = -k * (-point)
        return scalar_mult(-k, point_neg(point))

    result = None
    addend = point

    while k:
        if k & 1:
            # Add.
            result = point_add(result, addend)

            # Double.
            addend = point_add(addend, addend)

        k >>= 1

    return result


# Keypair generation
def make_keypair():
    """Generate a random private-public skey pair"""
    private_key = random.randrange(1, curve.n)
    public_key = scalar_mult(private_key, curve.g)

    return private_key, public_key


private, pub = make_keypair()
r = random.randint(0, 2 ** 128)
S = scalar_mult(r, pub)
""" This skey is an EC point, so it is then transformed
to 256-bit AES secret skey (integer) though hashing the point's x and y coordinates """
key = hashlib.sha256(str(S[0]).encode()).digest()


# AES function for encryption
def encrypt(plaintext, pubkey, mode):
    encode = AES.new(pubkey, mode)
    return encode.encrypt(plaintext)


rG = scalar_mult(r, curve.g)
Snew = scalar_mult(private, rG)
skey = hashlib.sha256(str(Snew[0]).encode()).digest()


# AES function for Decryption
def decrypt(cipher, privatekey, mode):
    decode = AES.new(privatekey, mode)
    return decode.decrypt(cipher)


# Application using tkinter

# Window CREATOR
wn = Tk()
wn.geometry("700x500")
wn.configure(bg='azure2')
wn.title("Encrypt and Decrypt Messages")

# Variables we will need
browse_text = StringVar()
Encrypted = StringVar()
ExtractedPDF = None

# Setting the widgets
headingFrame1 = Frame(wn, bg="gray91", bd=5)
headingFrame1.place(relx=0.2, rely=0.1, relwidth=0.7, relheight=0.16)

headingLabel = Label(headingFrame1, text=" Elliptic Curve \nCryptography", fg='grey19',
                     font=('Courier', 15, 'bold'))
headingLabel.place(relx=0, rely=0, relwidth=1, relheight=1)

label1 = Label(wn, text='Enter the Message', font=('Courier', 10))
label1.place(x=10, y=150)

Message = Text(wn, height=5, width=60, font=('calibre', 10, 'normal'))
Message.place(x=200, y=150)

label2 = Label(wn, text='Or Choose A PDF File', font=('Courier', 10))
label2.place(x=10, y=250)

EncMsg = Entry(wn, textvariable=Encrypted, width=60, font=('calibre', 10, 'normal'))
EncMsg.pack(padx=10, pady=10)
EncMsg.place(x=200, y=290, height=40)

Decrypted = Text(wn, height=5, width=60, font=('calibre', 10, 'normal'))
Decrypted.place(x=200, y=350)


# Function to Encrypt text
def OutEncrypted():
    Enc = Message.get(1.0, "end-1c")
    if Enc:
        new_string = Padding.appendPadding(Enc, blocksize=Padding.AES_blocksize, mode=0)
        EncryptedText = encrypt(new_string.encode(), key, AES.MODE_ECB)
        Encrypted.set(binascii.hexlify(EncryptedText))
        return EncryptedText
    else:
        messagebox.showinfo('Error', 'Please Choose text for Encryption and Decryption. Try again.')


# Function to extract text from pdf file
def open_file():
    global ExtractedPDF
    browse_text.set("loading...")
    file = askopenfile(mode='rb', title="Choose a file", filetypes=[("Pdf file", "*.pdf")])
    if not file:
        browse_text.set("Browse")

    read_pdf = PyPDF2.PdfFileReader(file)
    page = read_pdf.getPage(0)
    page_content = page.extractText()
    ExtractedPDF = str(page_content)
    browse_text.set("Browse")
    return ExtractedPDF


# Function to show the extracted text from Pdf in the message box
def pdfEncrypted():
    Message.insert(1.0, ExtractedPDF)


# Function to Decrypt text
def OutDecrypted():
    Dec = OutEncrypted()
    c = decrypt(Dec, skey, AES.MODE_ECB)
    DecryptedText = Padding.removePadding(c.decode(), mode=0)
    Decrypted.insert(1.0, DecryptedText)


# Function that executes on clicking Reset function
def Reset():
    Message.delete('1.0', END)
    browse_text.set("Browse")
    Encrypted.set("")
    Decrypted.delete('1.0', END)


# declaring buttons
browse_btn = Button(wn, textvariable=browse_text, font="Raleway", bg="#20bebe", fg="black", height=0,
                    width=10, command=lambda: [open_file(), pdfEncrypted()])
browse_btn.place(x=200, y=243)
browse_text.set("Browse")

EncBtn = Button(wn, text="Encrypt Message", bg='lavender blush2', fg='black', width=15, height=1, command=OutEncrypted)
EncBtn['font'] = font.Font(size=12)
EncBtn.place(x=10, y=290)

DecBtn = Button(wn, text="Decrypt Message", bg='lavender blush2', fg='black', width=15, height=1, command=OutDecrypted)
DecBtn['font'] = font.Font(size=12)
DecBtn.place(x=10, y=350)

ResetBtn = Button(wn, text='Reset', bg='honeydew2', fg='black', width=15, height=1, command=Reset)
ResetBtn['font'] = font.Font(size=12)
ResetBtn.place(x=15, y=450)

QuitBtn = Button(wn, text='Exit', bg='red', fg='black', width=15, height=1, command=wn.destroy)
QuitBtn['font'] = font.Font(size=12)
QuitBtn.place(x=200, y=450)

wn.mainloop()
