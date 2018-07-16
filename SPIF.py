
#SPIF is an image encryption algorithm, this is the CLI and Python module's code:

#Copyright (C) 2018  Elijah F. Hopp (A.K.A Mr.Zeus)
    
#This program is free software; you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation; either version 2 of the License, or
#(at your option) any later version.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License along
#with this program; if not, write to the Free Software Foundation, Inc.,
#51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#-----------------------------------WELCOME----------------------------------#
# WELCOME, there is two things I need to say before you go looking through my code/modifying it(check out the licence for more on that):
#I sometimes use short hand, here are a few examples:
#       A. char = charater
#       B. end_table(s) = encryption and decryption table(s)
#And, if you don't understand/think you could improve my code email me(Mr.Zeus) at github.mrzeusgaming@gmail.com, or contribute to the github project: https://github.com/MrZeusGaming/SPIF-image-encryption/
#----------------------------------------------------------------------------#

#This is part of a gist called "colortrans.py" (https://gist.github.com/pablox-cl/6567571) and was written by 
#pablox-cl (gist:https://gist.github.com/pablox-cl, github:https://github.com/pablox-cl/).
#Skip to line 401 to get to the code I wrote.


#----------------------------------------------------------------------------#
#I had to comment out the next 18 lines b/c they would mess up my module's docstrings.
#""" Convert values between RGB hex codes and xterm-256 color codes.
#
#Nice long listing of all 256 colors and their codes. Useful for
#developing console color themes, or even script output schemes.

#Resources:
#* http://en.wikipedia.org/wiki/8-bit_color
#* http://en.wikipedia.org/wiki/ANSI_escape_code
#* /usr/share/X11/rgb.txt

#I'm not sure where this script was inspired from. I think I must have
#written it from scratch, though it's been several years now.
#"""

#__author__    = 'Micah Elliott http://MicahElliott.com'
#__version__   = '0.1'
#__copyright__ = 'Copyright (C) 2011 Micah Elliott.  All rights reserved.'
#__license__   = 'WTFPL http://sam.zoy.org/wtfpl/'

#--------------------------------------------------------------------- Ingore this, it is part of pab's code, not mine

import sys, re

CLUT = [  # color look-up table
#    8-bit, RGB hex

    # Primary 3-bit (8 colors). Unique representation!
    ('00',  '000000'),
    ('01',  '800000'),
    ('02',  '008000'),
    ('03',  '808000'),
    ('04',  '000080'),
    ('05',  '800080'),
    ('06',  '008080'),
    ('07',  'c0c0c0'),

    # Equivalent "bright" versions of original 8 colors.
    ('08',  '808080'),
    ('09',  'ff0000'),
    ('10',  '00ff00'),
    ('11',  'ffff00'),
    ('12',  '0000ff'),
    ('13',  'ff00ff'),
    ('14',  '00ffff'),
    ('15',  'ffffff'),

    # Strictly ascending.
    ('16',  '000000'),
    ('17',  '00005f'),
    ('18',  '000087'),
    ('19',  '0000af'),
    ('20',  '0000d7'),
    ('21',  '0000ff'),
    ('22',  '005f00'),
    ('23',  '005f5f'),
    ('24',  '005f87'),
    ('25',  '005faf'),
    ('26',  '005fd7'),
    ('27',  '005fff'),
    ('28',  '008700'),
    ('29',  '00875f'),
    ('30',  '008787'),
    ('31',  '0087af'),
    ('32',  '0087d7'),
    ('33',  '0087ff'),
    ('34',  '00af00'),
    ('35',  '00af5f'),
    ('36',  '00af87'),
    ('37',  '00afaf'),
    ('38',  '00afd7'),
    ('39',  '00afff'),
    ('40',  '00d700'),
    ('41',  '00d75f'),
    ('42',  '00d787'),
    ('43',  '00d7af'),
    ('44',  '00d7d7'),
    ('45',  '00d7ff'),
    ('46',  '00ff00'),
    ('47',  '00ff5f'),
    ('48',  '00ff87'),
    ('49',  '00ffaf'),
    ('50',  '00ffd7'),
    ('51',  '00ffff'),
    ('52',  '5f0000'),
    ('53',  '5f005f'),
    ('54',  '5f0087'),
    ('55',  '5f00af'),
    ('56',  '5f00d7'),
    ('57',  '5f00ff'),
    ('58',  '5f5f00'),
    ('59',  '5f5f5f'),
    ('60',  '5f5f87'),
    ('61',  '5f5faf'),
    ('62',  '5f5fd7'),
    ('63',  '5f5fff'),
    ('64',  '5f8700'),
    ('65',  '5f875f'),
    ('66',  '5f8787'),
    ('67',  '5f87af'),
    ('68',  '5f87d7'),
    ('69',  '5f87ff'),
    ('70',  '5faf00'),
    ('71',  '5faf5f'),
    ('72',  '5faf87'),
    ('73',  '5fafaf'),
    ('74',  '5fafd7'),
    ('75',  '5fafff'),
    ('76',  '5fd700'),
    ('77',  '5fd75f'),
    ('78',  '5fd787'),
    ('79',  '5fd7af'),
    ('80',  '5fd7d7'),
    ('81',  '5fd7ff'),
    ('82',  '5fff00'),
    ('83',  '5fff5f'),
    ('84',  '5fff87'),
    ('85',  '5fffaf'),
    ('86',  '5fffd7'),
    ('87',  '5fffff'),
    ('88',  '870000'),
    ('89',  '87005f'),
    ('90',  '870087'),
    ('91',  '8700af'),
    ('92',  '8700d7'),
    ('93',  '8700ff'),
    ('94',  '875f00'),
    ('95',  '875f5f'),
    ('96',  '875f87'),
    ('97',  '875faf'),
    ('98',  '875fd7'),
    ('99',  '875fff'),
    ('100', '878700'),
    ('101', '87875f'),
    ('102', '878787'),
    ('103', '8787af'),
    ('104', '8787d7'),
    ('105', '8787ff'),
    ('106', '87af00'),
    ('107', '87af5f'),
    ('108', '87af87'),
    ('109', '87afaf'),
    ('110', '87afd7'),
    ('111', '87afff'),
    ('112', '87d700'),
    ('113', '87d75f'),
    ('114', '87d787'),
    ('115', '87d7af'),
    ('116', '87d7d7'),
    ('117', '87d7ff'),
    ('118', '87ff00'),
    ('119', '87ff5f'),
    ('120', '87ff87'),
    ('121', '87ffaf'),
    ('122', '87ffd7'),
    ('123', '87ffff'),
    ('124', 'af0000'),
    ('125', 'af005f'),
    ('126', 'af0087'),
    ('127', 'af00af'),
    ('128', 'af00d7'),
    ('129', 'af00ff'),
    ('130', 'af5f00'),
    ('131', 'af5f5f'),
    ('132', 'af5f87'),
    ('133', 'af5faf'),
    ('134', 'af5fd7'),
    ('135', 'af5fff'),
    ('136', 'af8700'),
    ('137', 'af875f'),
    ('138', 'af8787'),
    ('139', 'af87af'),
    ('140', 'af87d7'),
    ('141', 'af87ff'),
    ('142', 'afaf00'),
    ('143', 'afaf5f'),
    ('144', 'afaf87'),
    ('145', 'afafaf'),
    ('146', 'afafd7'),
    ('147', 'afafff'),
    ('148', 'afd700'),
    ('149', 'afd75f'),
    ('150', 'afd787'),
    ('151', 'afd7af'),
    ('152', 'afd7d7'),
    ('153', 'afd7ff'),
    ('154', 'afff00'),
    ('155', 'afff5f'),
    ('156', 'afff87'),
    ('157', 'afffaf'),
    ('158', 'afffd7'),
    ('159', 'afffff'),
    ('160', 'd70000'),
    ('161', 'd7005f'),
    ('162', 'd70087'),
    ('163', 'd700af'),
    ('164', 'd700d7'),
    ('165', 'd700ff'),
    ('166', 'd75f00'),
    ('167', 'd75f5f'),
    ('168', 'd75f87'),
    ('169', 'd75faf'),
    ('170', 'd75fd7'),
    ('171', 'd75fff'),
    ('172', 'd78700'),
    ('173', 'd7875f'),
    ('174', 'd78787'),
    ('175', 'd787af'),
    ('176', 'd787d7'),
    ('177', 'd787ff'),
    ('178', 'd7af00'),
    ('179', 'd7af5f'),
    ('180', 'd7af87'),
    ('181', 'd7afaf'),
    ('182', 'd7afd7'),
    ('183', 'd7afff'),
    ('184', 'd7d700'),
    ('185', 'd7d75f'),
    ('186', 'd7d787'),
    ('187', 'd7d7af'),
    ('188', 'd7d7d7'),
    ('189', 'd7d7ff'),
    ('190', 'd7ff00'),
    ('191', 'd7ff5f'),
    ('192', 'd7ff87'),
    ('193', 'd7ffaf'),
    ('194', 'd7ffd7'),
    ('195', 'd7ffff'),
    ('196', 'ff0000'),
    ('197', 'ff005f'),
    ('198', 'ff0087'),
    ('199', 'ff00af'),
    ('200', 'ff00d7'),
    ('201', 'ff00ff'),
    ('202', 'ff5f00'),
    ('203', 'ff5f5f'),
    ('204', 'ff5f87'),
    ('205', 'ff5faf'),
    ('206', 'ff5fd7'),
    ('207', 'ff5fff'),
    ('208', 'ff8700'),
    ('209', 'ff875f'),
    ('210', 'ff8787'),
    ('211', 'ff87af'),
    ('212', 'ff87d7'),
    ('213', 'ff87ff'),
    ('214', 'ffaf00'),
    ('215', 'ffaf5f'),
    ('216', 'ffaf87'),
    ('217', 'ffafaf'),
    ('218', 'ffafd7'),
    ('219', 'ffafff'),
    ('220', 'ffd700'),
    ('221', 'ffd75f'),
    ('222', 'ffd787'),
    ('223', 'ffd7af'),
    ('224', 'ffd7d7'),
    ('225', 'ffd7ff'),
    ('226', 'ffff00'),
    ('227', 'ffff5f'),
    ('228', 'ffff87'),
    ('229', 'ffffaf'),
    ('230', 'ffffd7'),
    ('231', 'ffffff'),

    # Gray-scale range.
    ('232', '080808'),
    ('233', '121212'),
    ('234', '1c1c1c'),
    ('235', '262626'),
    ('236', '303030'),
    ('237', '3a3a3a'),
    ('238', '444444'),
    ('239', '4e4e4e'),
    ('240', '585858'),
    ('241', '626262'),
    ('242', '6c6c6c'),
    ('243', '767676'),
    ('244', '808080'),
    ('245', '8a8a8a'),
    ('246', '949494'),
    ('247', '9e9e9e'),
    ('248', 'a8a8a8'),
    ('249', 'b2b2b2'),
    ('250', 'bcbcbc'),
    ('251', 'c6c6c6'),
    ('252', 'd0d0d0'),
    ('253', 'dadada'),
    ('254', 'e4e4e4'),
    ('255', 'eeeeee'),
]

def _str2hex(hexstr):
    return int(hexstr, 16)

def _strip_hash(rgb):
    # Strip leading `#` if exists.
    if rgb.startswith('#'):
        rgb = rgb.lstrip('#')
    return rgb

def _create_dicts():
    short2rgb_dict = dict(CLUT)
    rgb2short_dict = {}
    for k, v in short2rgb_dict.items():
        rgb2short_dict[v] = k
    return rgb2short_dict, short2rgb_dict

def short2rgb(short):
    return SHORT2RGB_DICT[short]

def print_all():
    """ Print all 256 xterm color codes.
    """
    for short, rgb in CLUT:
        sys.stdout.write('\033[48;5;%sm%s:%s' % (short, short, rgb))
        sys.stdout.write("\033[0m  ")
        sys.stdout.write('\033[38;5;%sm%s:%s' % (short, short, rgb))
        sys.stdout.write("\033[0m\n")
    print("Printed all codes.")
    print("You can translate a hex or 0-255 code by providing an argument.")

def rgb2short(rgb):
    """ Find the closest xterm-256 approximation to the given RGB value.
    @param rgb: Hex code representing an RGB value, eg, 'abcdef'
    @returns: String between 0 and 255, compatible with xterm.
    >>> rgb2short('123456')
    ('23', '005f5f')
    >>> rgb2short('ffffff')
    ('231', 'ffffff')
    >>> rgb2short('0DADD6') # vimeo logo
    ('38', '00afd7')
    >>> rgb2short('3D3D3D')
    ('237', '3a3a3a')
    >>> rgb2short('070707')
    ('232', '080808')
    """
    rgb = _strip_hash(rgb)
    # Break 6-char RGB code into 3 integer vals.
    parts = [ int(h, 16) for h in re.split(r'(..)(..)(..)', rgb)[1:4] ]

    incs = [0x00, 0x5f, 0x87, 0xaf, 0xd7, 0xff]

    if parts[0] == parts[1] == parts[2]:
        gs_incs = range(0x08, 0xee, 10)
        incs = sorted(list(incs)+list(gs_incs)+[0xee,]) #I removed spaces from this line, and made them all lists, had some dumb error talking 'bout it

    res = []
    for part in parts:
        i = 0
        while i < len(incs)-1:
            s, b = incs[i], incs[i+1]  # smaller, bigger
            if s <= part <= b:
                s1 = abs(s - part)
                b1 = abs(b - part)
                if s1 < b1: closest = s
                else: closest = b
                res.append(closest)
                break
            i += 1
    #print '***', res
    res = ''.join([ ('%02.x' % i) for i in res ])
    equiv = RGB2SHORT_DICT[ res ]
    #print '***', res, equiv
    return equiv, res

RGB2SHORT_DICT, SHORT2RGB_DICT = _create_dicts()

#---------------------------------------------------------------------
#if __name__ == '__main__':   This was also commented out so it would not mess up my code.
#   import doctest
#   doctest.testmod()
#   if len(sys.argv) == 1:
#       print_all()
#       raise SystemExit
#   arg = sys.argv[1]
#   if len(arg) < 4 and int(arg) < 256:
#       rgb = short2rgb(arg)
#       sys.stdout.write('xterm color \033[38;5;%sm%s\033[0m -> RGB exact \033[38;5;%sm%s\033[0m' % (arg, arg, arg, rgb))
#       sys.stdout.write("\033[0m\n")
#   else:
#       short, rgb = rgb2short(arg)
#       sys.stdout.write('RGB %s -> xterm color approx \033[38;5;%sm%s (%s)' % (arg, short, short, rgb))
#       sys.stdout.write("\033[0m\n")
#----------------------------------------------------------------------------#
#WELCOME TO MY CODE!
#Import modules:
from PIL import Image
from random import randint
from sys import argv, excepthook, stdout
from os import _exit
from importlib import import_module
from textwrap import wrap
from datetime import datetime
import logging
from traceback import format_exception, print_exc
import multiprocessing
from argparse import ArgumentParser
#----------------------------------------------------------------------------#
if __name__ == "__main__":
    #Set up some stuff for logging:
    logging.basicConfig(filename="SPIF.log", 
        filemode="w", 
        format="[%(asctime)s,%(msecs)03d]:%(name)s:%(levelname)s:%(message)s",
        level=logging.CRITICAL,
        datefmt="%m/%d/%Y-%I:%M:%S")
log = logging.getLogger("SPIF_LOG")
log.setLevel(logging.DEBUG)
#State that the script has started:
log.info("Log setup done, starting...")
#Make it so all uncaught exceptions are both logged and printed:
if __name__ == "__main__":
    def log_except_hook(*exc_info):
        error = "".join(format_exception(*exc_info))
        log.error("UNHANDLED EXCEPTION: \n%s"%error)
        print("%s"%error, end="")
    sys.excepthook = log_except_hook
#----------------------------------------------------------------------------#
#Declare some global vars:
spif_datetime = datetime.now()
#Make a variable to hold the version:
spif_version = "V1.0"
#Highest encryption/decryption level var:
highest_e_level = 1
#Highest multiprocessed encryption/decryption level:
highest_mp_e_level = 0
#Make a list of every numbers in the ASCII charater set:
ASCII_numbers = [
    "0",
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "8",
    "9",
]
#Make a table to encrypt the numbers in the file header, and antother to decrypt them.
#(For more info on the file header confer the commented off section below the global variable section)
HENT = {
    "0":">",
    "1":"©",
    "2":"j",
    "3":"M",
    "4":")",
    "5":"/",
    "6":"7",
    "7":"å",
    "8":"_",
    "9":"e"
}
HDET = {
    ">":"0",
    "©":"1",
    "j":"2",
    "M":"3",
    ")":"4",
    "/":"5",
    "7":"6",
    "å":"7",
    "_":"8",
    "e":"9"
}
#-----------------------------FILE_HEADER_INFO------------------------------#
#The header format is as follows, "AAAAAAAAAAAAAAA<width>Ⱥ<hieght>AAAAAAAAAAAAAAA", where "Ⱥ"
#(Just a note, there are 15 chars each sides, so you don't have to count)
#Is a pseudo randomly selected letter, number, or symbol.
#The "<width>Ⱥ<height>" part of it is the resolution. The width and height are encrypted
#with the HDET to make the text file seem like a normal encrypted text file.
#----------------------------------------------------------------------------#
#Set up some helper functions(till line 515):
def garble(garble_length=15):
    #Make a variable to hold the garble that is returned
    returned_garble = ""
    for i in range(garble_length):
        #Make a random char that is a printable charater
        garble_int = randint(0, 255)+33
        #Add the "chr"ed int to the returned garble
        returned_garble = returned_garble+chr(garble_int)
    #And finnally return the garble
    return returned_garble


def make_file_header(width, height):
    #The final product that is going to return:
    header = ""
    #Add 15 picece of garble to the file header, read the file header 
    #section to know the format of the file header is supposed to.
    header = header+garble()
    #Make sure the width is a string
    width = str(width)
    #For every character in the width string
    for i in range(len(width)):
        #Make sure that the width variable is a number
        if width[i:i+1] not in ASCII_numbers:
            #If width is not a number, raise a TypeError
            raise TypeError('"width" is not a number in the ASCII charater set')
        #Add the encrypted charater to the header
        header = header+HENT[width[i:i+1]]
    #Add the required "Ⱥ" character to the header, following SPIF file header standards
    header = header+"Ⱥ"
    #Make sure the height is a string, just like width
    height = str(height)
    #For every charater in the height string
    for i in range(len(height)):
        #If the current charater is not a number
        if height[i:i+1] not in ASCII_numbers:
            #If height is not a number raise a TypeError
            raise TypeError('"height" is not a number in the ASCII charater set')
        header = header+HENT[height[i:i+1]]
    #Add another 15 picece of garble to the end of the file header
    header = header+garble()
    #And finally return the encrypted file header
    return header


def indexes_from_hex_2_ints(_2_ints_list):
    returned_list = []
    for i in range(len(_2_ints_list)):
        returned_list.append(int(_2_ints_list[i],16))
    return returned_list


def import_end_tables(end_path):
    #This simply makes it easier import the end tables:
    global end_tables 
    end_tables = import_module(end_path.strip(".py"))
    try:
        end_tables.int_2_colour
        end_tables.colour_2_int
    except AttributeError:
        print_exc()
        logging.error("The supplied end_tables file did not meet the requirements, exiting...")
        return False
        _exit(3)


#----------------------------------------------------------------------------#
#These are the important functions:
def spif_encrypt(end_tables_path, input_file_name, output_file_name="spif_out.txt",_encryption_level=0, spif_mute=False, _timeit=True):
    """YOLO"""
    #Set up a date time if the _timeit arg is True:
    start_time = datetime.now() if _timeit == True else None
    #Open the file containing the end tables
    log.info('spif_encrypt was called with the following args:\nend_tables_path="%s",\ninput_file_name="%s",\noutput_file_name="%s",\n_encryption_level=%s,\nspif_mute=%s\n_timeit=%s'%
    (end_tables_path,input_file_name,output_file_name,_encryption_level,spif_mute,_timeit))
    #Log the SPIF version:
    log.info("Starting SPIF %s..."%spif_version)
    #Print that that the program has started and the time it was started, if the spif_mute args is NOT true
    print("Starting SPIF %s(https://github.com/MrZeusGaming/SPIF-image-encryption) at %s"%(spif_version, spif_datetime.strftime("%Y-%m-%d %H:%M:%S"))) if spif_mute != True else None
    #Try to import the end tables:
    import_end_tables(end_tables_path)
    log.debug("spif_encrypt imported the end_tables and it met all requirements...")
    if _encryption_level > highest_e_level:
        try:
            raise ValueError("Illegal encryption level: %s"%_encryption_level)
        except ValueError:
            print_exc()
            logging.error("User tried to use a higher encryption level than avalible, exiting...")
            return False
            _exit(2)
    #Open the un-SPIFed image file, and load it
    im = Image.open(input_file_name)
    loaded_image = im.load()
    #Log it:
    log.debug("The image was opened and loaded...")
    #Get the width and height of the loaded image
    width, height = im.size
    log.info("The image's width and height are %s and %s..."%(width,height))
    #State the name of the file, and the end_tables file's name:
    print('Processing "%s" with "%s" as an EnD Tables file.'%(input_file_name, end_tables.__name__)) if spif_mute != True else None
    #State the size of the image:
    print("Your image is %s pixels by %s pixels."%(str(width),str(height))) if spif_mute != True else None
    #Open the output file:
    spifed_image_file = open(output_file_name, mode="w")
    #Say SPIF are doing things
    if _encryption_level == 0:
        #thE mAn löp:
        for Y in range(height):
            for X in range(width):
                spifed_image_file.write(chr(end_tables.colour_2_int[rgb2short("".join("{:02X}".format(pix) for pix in loaded_image[X,Y][:3]))[1]]))
            spifed_image_file.write("\n")
    #The following two comments were ment to go in the in the for X loop but due to performance they were moved here:
    #This has got to be one of my longest one-liners yet, I love hacking!
    #Also thanks to Kevin from SO(StackOverflow) for the .join part of it, huge help!
    elif _encryption_level == 1:
        spifed_image_file.write(make_file_header(width,height)+"\n")
        for Y in range(height):
            for X in range(width):
                spifed_image_file.write(chr(end_tables.colour_2_int[rgb2short("".join("{:02X}".format(pix) for pix in loaded_image[X,Y][:3]))[1]])+garble(3))
            spifed_image_file.write(garble(randint(0,25))+"\n")
    spifed_image_file.close()
    #Print saying that the encryption progress fininshed:
    print("The encryption progress has finished.") if spif_mute != True else None
    #Get the elapsed time:
    elapsed_time = datetime.now()-start_time if _timeit == True else None
    #Print the elasped time:
    print("%s.%s seconds elapsed."%(elapsed_time.seconds,elapsed_time.microseconds)) if spif_mute != True and _timeit == True else None
    #Just do a quick newline so it will look better:
    print("") if spif_mute != True else None
    #Return True just in case someone wants a bool to let them know everything went as planned
    return True

def spif_decrypt(end_tables_path, input_file_name, output_file_name="spif_out.png", _encryption_level=0, spif_mute=False, _timeit=True):
    """LET'S YOLO IT BRO"""
    #Make a variable to hold the start datetime:
    start_time = datetime.now()
    #Print all the args passed to the function:
    log.info('spif_decrypt was called with the following args:\nend_tables_path="%s",\ninput_file_name="%s",\noutput_file_name="%s",\n_encryption_level=%s,\nspif_mute=%s'%
    (end_tables_path,input_file_name,output_file_name,_encryption_level,spif_mute))
    #Log the SPIF version:
    log.info("Starting SPIF %s..."%spif_version)
    #Print that that the program has started and the time it was started, if the spif_mute args is NOT true
    print("Starting SPIF %s(https://github.com/MrZeusGaming/SPIF-image-encryption) at %s"%(spif_version,spif_datetime.strftime("%Y-%m-%d %H:%M:%S"))) if spif_mute != True else None
    #Open the file containing the end tables:
    import_end_tables(end_tables_path)
    #Confirm that the end_tables met all its requirements:
    log.debug("spif_decrypt imported the end_tables and it met all requirements...")
    if _encryption_level > highest_e_level:
        try:
            raise ValueError("Illegal encryption level: %s"%_encryption_level)
        except ValueError:
            print_exc()
            logging.error("User tried to use a higher encryption level than avalible, exiting...")
            return False
            _exit(2)
    #State the name of the file, and the end_tables file's name:
    print('Processing "%s" with "%s" as an EnD Tables file.'%(input_file_name, end_tables.__name__)) if spif_mute != True else None
    if _encryption_level == 0:
        #The file encrypted by SPIF:
        spifed_file = open(input_file_name, "r")
        #Create a variable to hold all the lines of the file:
        spifed_file_lines = spifed_file.read().split("\n")
        #Print the width and height of the encrypted file:
        print("Your encypted image is %s pixels by %s pixels."%(len(spifed_file_lines[0]),len(spifed_file_lines)-1)) if spif_mute != True else None
        #Make a variable that holds the output image:
        decrypted_spif_file = Image.new("RGB", (len(spifed_file_lines[0]), len(spifed_file_lines)-1))
        #Now this is loop, it is quite complex:
        for i in range(len(spifed_file_lines)-1):
            for j in range(len(spifed_file_lines[0])):
                decrypted_spif_file.putpixel((j,i), tuple(indexes_from_hex_2_ints(wrap(end_tables.int_2_colour[ord(spifed_file_lines[i][j])], 2))))
        #And finally save the image:
        decrypted_spif_file.save(output_file_name,format="PNG")
    elif _encryption_level == 1:
        #The file encrypted by SPIF:
        spifed_file = open(input_file_name, "r")
        #Read the file header:
        spifed_file_header = spifed_file.readline().strip("\n").split("Ⱥ")
        #Get the height and width of the SPIFed file:
        print("The header is: "+"Ⱥ".join(spifed_file_header)) if spif_mute != True else None
        #Get the height and width of the level 1 SPIFed file:
        spifed_file_height = int("".join(HDET[part] for part in list(spifed_file_header[1][:len(spifed_file_header[1])-15])))
        spifed_file_width = int("".join(HDET[part] for part in list(spifed_file_header[0][15:])))
        print("Your encypted image is %s pixels by %s pixels."%(spifed_file_height, spifed_file_width)) if spif_mute != True else None
        #Create a variable to hold all the lines of the file:
        spifed_file_lines = spifed_file.read().split("\n")
        #Make a variable that holds the output image:
        decrypted_spif_file = Image.new("RGB", (spifed_file_width, spifed_file_height))
        #This is the main piece of code I spent hours slaving over, 
        #just to get it to work properly. So much sleep has been lost over this...
        for Y in range(spifed_file_height):
            image_X = 0
            for X in range(0, spifed_file_width*4, 4):
                decrypted_spif_file.putpixel((image_X,Y), tuple(indexes_from_hex_2_ints(wrap(end_tables.int_2_colour[ord(spifed_file_lines[Y][X])],2))))
                image_X += 1
        #And finally save the image:
        decrypted_spif_file.save(output_file_name,format="PNG")
    #Print saying that the encryption progress fininshed:
    print("The decryption progress has finished.") if spif_mute != True else None
    #Get the elapsed time:
    elapsed_time = datetime.now()-start_time if _timeit == True else None
    #Print the elasped time:
    print("%s.%s seconds elapsed."%(elapsed_time.seconds,elapsed_time.microseconds)) if spif_mute != True and _timeit == True else None
    print("") if spif_mute != True else None


"""
def spif_mp_encrypt(end_tables_path, input_file_name, num_threads=2,output_file_name="spif_out.png", _encryption_level=0, spif_mute=False):
    log.info('spif_mp_encrypt was called with the following args:\nend_tables_path="%s",\ninput_file_name="%s",\nnum_threads=%s,\noutput_file_name="%s",\n_encryption_level=%s,\nspif_mute=%s'%
    (end_tables_path,input_file_name,num_threads,output_file_name,_encryption_level,spif_mute))
    #Log the SPIF version:
    log.info("Starting SPIF MultiProcessed(Testing)%s..."%spif_version)
    #Print that that the program has started and the time it was started, if the spif_mute args is NOT true
    print("Starting SPIF MultiProcessed(Testing) %s(https://github.com/MrZeusGaming/SPIF-image-encryption) at %s"%(spif_version,spif_datetime.strftime("%Y-%m-%d %H:%M:%S"))) if spif_mute != True else None
    #Open the file containing the end tables:
    import_end_tables(end_tables_path)
    #Confirm that the end_tables met all its requirements:
    log.debug("spif_decrypt imported the end_tables and it met all requirements...")
    if _encryption_level > highest_mp_e_level:
        try:
            raise ValueError("Illegal encryption level: %s"%_encryption_level)
        except ValueError:
            print_exc()
            logging.error("User tried to use a higher encryption level than avalible, exiting...")
            return False
            _exit(2)
    #State the name of the file, and the end_tables file's name:
    print('Processing "%s" on %s processes with "%s" as an EnD Tables file.'%(input_file_name, num_threads, end_tables.__name__)) if spif_mute != True else None
"""


#----------------------------------------------------------------------------#
#If the --help for -h flag is enabled show the help menu:
spif_ascii_logo = """\t  __________________________________
\t /   _____/\______   \   \_   _____/
\t \_____  \  |     ___/   ||    __)  
\t /        \ |    |   |   ||    |   
\t/_________/ |____|   |___|\____/   
\t                              
"""
#----------------------------------------------------------------------------#
#Start the main parsing of the args, if this file is not being imported.
_main = "__main__"
#_main = "_main__"
if __name__ == _main:
    log.debug("Entered the if-name-is-main for the CLA(Command-Line-Args) parsing...")
    #Set up the input file var
    input_file = ""
    #Set up the output files default name
    out_file = "spif_out.txt"
    #Set up the default encrytion level
    encryption_level = 0
    #Set up the argparse class:
    arg_parser = ArgumentParser(description="Not just any image-encryption CLI.")
    #Add a lot of arguments:
    arg_parser.add_argument("encrypt_or_decrypt", help="tell the CLI wether to encrypt or decrypt the input file", choices=["encrypt", "decrypt"])
    arg_parser.add_argument("input_file_path", help="set the input file path.")
    arg_parser.add_argument("end_table_path", help="set the path to the end_table (Encryption aNd Decryption TABLE).")
    arg_parser.add_argument("-e", "--e_level", help="set the encryption or decryption level", dest="e_level", default=0, type=int, metavar="encryption_level")
    arg_parser.add_argument("-o", "--output", help="set the name of the output file. note: file extensions are removed", dest="output_path", default="spif_out", metavar="output_path")
    arg_parser.add_argument("-m", "--mute", help="tell SPIF to shut up, i.e. don't print anything to stdout.", dest="mute", action="store_true")
    arg_parser.add_argument("--version", action="version", version="SPIF %s"%spif_version)
    #Parse the args:
    args = arg_parser.parse_args()
    if args.encrypt_or_decrypt == "encrypt":
        #If the output path does NOT end with ".txt" be kind to the user and add it as the file extension:
        if not args.output_path.endswith(".txt"):
            args.output_path = args.output_path+".txt"
        #Call SPIF encrypt with the proper 
        spif_encrypt(args.end_table_path, args.input_file_path, args.output_path, args.e_level, args.mute)
    elif args.encrypt_or_decrypt == "decrypt":
        if not args.output_path.endswith(".png"):
            args.output_path = args.output_path+".png"
        spif_decrypt(args.end_table_path, args.input_file_path, args.output_path, args.e_level, args.mute)
#--------------------------TESTING_GROUNDS-----------------------------------#
#spif_encrypt("DETF.py", "simple_8x8.png", _encryption_level=1)
#spif_decrypt("DETF.py", "spif_out.txt", _encryption_level=1)
