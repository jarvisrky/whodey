import time
import sys

PALETTE = [(255, 255, 255), (254, 254, 250), (226, 222, 199), (131, 173, 168), (89, 177, 189), (86, 167, 179), (66, 169, 183), (62, 163, 178), (189, 145, 109), (93, 150, 155), (68, 157, 171), (67, 145, 159), (53, 157, 173), (53, 147, 164), (54, 138, 155), (44, 137, 154), (185, 120, 82), (171, 116, 84), (176, 105, 68), (165, 103, 72), (188, 90, 31), (182, 83, 23), (164, 96, 63), (162, 89, 53), (149, 103, 74), (149, 90, 61), (152, 84, 52), (143, 83, 54), (107, 105, 96), (114, 84, 69), (46, 129, 146), (56, 106, 116), (165, 76, 28), (158, 67, 19), (142, 76, 47), (140, 67, 33), (123, 74, 51), (122, 65, 39), (101, 73, 61), (100, 64, 49), (140, 55, 20), (124, 53, 25), (103, 57, 38), (103, 50, 27), (124, 39, 14), (124, 27, 10), (101, 38, 15), (99, 24, 9), (82, 62, 57), (62, 62, 62), (75, 49, 41), (56, 48, 53), (78, 37, 19), (62, 39, 37), (51, 39, 45), (41, 36, 41), (69, 26, 12), (42, 25, 24), (73, 17, 7), (46, 18, 10), (29, 19, 17), (18, 11, 11), (16, 7, 9), (11, 5, 8)]
SYMBOLS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+-"
MEME = """
IZqquqqqhqyyyyyxiWZieeeeeiilbGJbdddaPOJHGGOaJJ8GRRNRoyoP8GGWwlZQNQhuxxxkZffeeXWK
WZuuuquqqkvyyyyxeWeZWWeeefkuuPJddddcTTOHHJPTdcTagaParzvrP8IKflfbZYfuqquqfffZfeeW
XWkqxvyxqkqyyyxuXWWZZfiikklkuqbddddccTTOOPPTTTdgogactzvprGGWNiYZeNYfZbukffhhffiX
WWfhquxxuqgvyyxuZXKZZfiflwlfqqbdccdmccTTTOOTOORaoodmvytnrH8NWWZYNNYZYfbfZffhkieX
LXfZffhqqkgvyyxkeLGWWZiikwkqyxgodcccccTTTTTTRaaadmmoyysmdP8IWIffZYZZZZ8GZYYfkeei
LWfbghqqqhgvyyxkZMYfeffiqqqyyxgomdccccTTTTTTOOJJPmmsyvnmgQ8I88bbbffefR88ZfZffZfi
KQhuyzyxvqrvvyxqovweZbklqvyyyyooomccccTTTTTTTOOOTomtytmmbG8GOScccOJQN888NfbfbYhh
qvyzzzyyzyyvvvxvyxZNbquhryyznSmmopmmcccccTTTmooooorzypmdaI8GmpnnmO888888JfhhZMaq
z+zzzzzzzyyyyvxyyuffhxqqzzyv93ngdoommcccccTTcdddomTvypodbG8Imnnnnm88888OgkhfiWfw
z+z+z++zzzzzzyxyyhfhqubr+yzv949mddorrnmmcdcTTcccmT8HrxdaY88GmpnnppT88HHHPfbfjeel
+++zz++zzzzzzyyyuNWZkkbyzytV5649cddmorppmmmcccmmpd88RaabJ88GmpnnnnoOSSH88ONQljju
++++++++zzzzzyyzkNWZhkuy+t9456649mddmmoooponnpnV9oHHHOaYG88ImnnnnnnSSH8888GZljlx
+++++++++++zzzyyfZeZhqxzt995466659cddooomorrsrnU5STOJPYI888MmpnnppnSS88888Jjjjlx
++++++++++++zzzuYfZgquvt95BB4666669TcdooooorrrpVB9dOHJP8888PotpssppTO888HHJjjeur
++++++++++zzzz+kbqquxtn9994BB4666769SaddooooroonE9cPHHJ8888MctsspprrqaH8HHHejiuo
++++++++++++zz+hqxxytV94555BVB666676BSagooooomonEBSTJHOG888JaptssruuxuhOHHHejkxm
+++++++++++++-zuyz+n9999BBAB9UEA66676AScdoggddrnDD9STPPPJOHGPS9mqqqqquqfOHOjlwuc
+++++++++++++-zy--n3995955454AEUBA6676AVVSogdosVCDB9SpdaPOJHMO33TqqkihhhRORllwoT
++++++++--+---+-tV933555BAAAEDFUVUA77CUBAU38SSVVBBVU9VpaaPJGMPS33cuqkhYbdOdwlwdT
++++++++++-----n999355EBB5BEBBBBDB55A66EBU31239BEABEEBVoaRMHMPT343SqqqbbdTkllldT
+++++++++-----n954444453456545445A7CD7776CA325DDFDDCDA5naRRJJRaS499muqfZTPZeehcT
y--++++------t3555AAA7646CDEECDCCCDCDECCDDDU3EUUUUUUEDBVdaRJJRYT9B5SuqfYTafYbdcc
uy--------+--95BBEEEEEEEDDFBBAUEUUUUUEUUUFUUABB5BEEEEEA9maRMJRYaV533oqbaTgquuomm
qqyxvzxxzyz-p9EB5444445ABED45A65A54544544444954AA46AA555VdaPHPYYc343SuhdTgwxvomm
rruaaxqqxxx-n954456666655555CCA7557A67C67777DEDDFCDEDCDEUnaPHJRYaS59Sqhgagwwunmm
rpruquuuxuuvV55ACCCDDCCCC7557FUFEDDFFCFEDDEEUUUUUUUUUUUBEnaPJHPYRT333chgahwwrnmp
tsmouuuxxxur95AAEUUUUEEFFFFEBFDDFEUFBUUEUUFEUB5AABA55A5549dPJHMYYYS93ShgRPfuonmp
vrmTmxxxyyxt9BEUEA54444455ABUD445554454455445ACCD667777D79cRPHJQYNa93TkgbPMbonmt
srorovyzzz+tBUB54466776766456AACCCA77A77A76C7ADDFDCDDDDUB9daPJHMYNQS3SkhbPMHTppy
rrrmrrrvzz-tV9457CCCDDFDDDDDC55CCDDDDFEDEFDDFFFUUUUUUUEBESgaPJHJYQNYSSkkfPOOTvyz
rpsppssrvz-t95ACAAFFUFFCBBFFDDAUUUUUFEEUUEEED545555454453ScdPOHHPQMNTSgkkhbbaozz
rrssnstvvy-t9BABUFDA544466C645DCAA54445544444446A767C77C9TTdRPHGJQNMRSTkhffYPozz
ppppmnttvv+p9BUUB44467CCCCDFFDDA444567CAAAAA7777CCCDDCDBSTTdRPJGHQQMMROahfZZboyy
pnnppmtttvyn9UE4447CCCDDFFFEBA5CCCC7C7CDDDDEDEEUUUUUUUUVdOOdaMJHHJNJIQTHOfZZZhyy
ppmmmSpstvznBB5A777AEUUFA544455ADDDEUUUUUUUUUUFEBDA5554SaOOdaPMH8JMMIMYP8RaYZhyx
mmSScSmnpvynE55BBDFUFA544667CCCDUUUFDCA5555555444444544SPOOcbRMH8HMMIINYQJHJYhyv
npppscptsvyp59BAUUA44467CCCCFUUBAA64444556777777CCCCC7ASPOPcgRMH8GHMMIMQYQGGPgzv
sspnpmmtsvyt9AEEA45667CCDFUFD5445567CCCC7CCCAACABBDEUFETPPadgRMJH8GJMIINQQQGHozy
sspppnnstvvznBU946CCDFFFFD644677BFC7CCDEEUUUUUUUUUFEEC9TcaadgYPJH8GHMIIMQYQJ8ozz
tsspppnttvvyzV45BADEFDA546467ADEUFEFUUFFEDAAA5554544443cdaRbgYPJH88HJMIMNQQQHTzz
sssppsmSptyyzt9AAUUA54467CCDFFFDC7EDA544444444445567C69daRYagYQJHG8GIMJJNQYQMOxy
ttpnsnS23syvyzVBUB44667CEEFFDC766AA4446677CC77777AC7A9cbRRYYgaPMJH88GJMMNQYQQPur
ssppsp828TyvyztV5447ABEFFCC777B9SSVDCCC7AAACABDEEUEUcdYPRYYYgaPPJHG8GHMMMQYYYaqq
psspsS38H8syyy-V4AABFFCC77A99SHJMNcECDEFUUUUUFFEEBVcbRQMQYYRggPPJHG88HJNNQYYRdoo
ssppsnnpvstyyy+tBAEDC67799SHHIIIMMTVFFFEAA6544443ScaQNPPQRaagqPPPJH88HHNQQYaYgoo
sssspppSstvvvyzyVD76699SHJIGGGIIMNaV444444466659TbRRQNNQYRbbgraPPMHH8HHPPRabagoo
psspnpmSpstvvyyznA69SOOJIIGGGGIIMMRS66777C7779SaaYQQQQQYYabgmogPPPJH8HJPPYbbgooo
spppppnSpstvvvvzt99ORMIIIIGGGGGIMNRcE6ACDDBUScbYRQQQQQYYbbgnnmdaPPMJHHORaabdoooo
ppppmSSSSmsvvttyzSabRPMIIGGGGGGIMNQcVEFDBVmdbYYYQQQQQQYabdpUBnddaRPPHHOaabdmnroo
ssppmcmSnnnstvtv+ncbYQMJJGGGGGGIMNYaV659SdaYRRQQQYQYYYabopU6EnmTcaaRPJOTaddnSrro
pnpsppnSsstsstttxmSgYQPMJIGGGGGIMNYgV3SabYQQNNNQQYYYYbgotUEUU9pccddaROOTddonSnrs
npspnpnnppsstsstvvnmaYQMJJIGGGGIMNYbgabYQQNNNNNNQYYYagopUDDEA9pvmcddaPOcmooVVmst
tspspsnpppssttptsvpngYRPMJIHGGGGIMQYYQNNNMMMMMNQYYbbgotB54447AnyvocdddcmrgOSVSnr
tstsssptsssstvtppvyVcgYRPMJJIGGGIIMNNMMMMIIMNNNQYabgotV6DA67DUntttnmmoomO823VVmr
ttppsnsstttttvtpnrxn9mbYRPMMJIGGIIJMMJIIIJJMMNYYYbggsV7AEECDU9VnnnVnnnn82223npns
ttsssnppptttvvspnvxyBVobYRPMMJGGGHHHHHJJJJMMQYYYbggrnUUUUUUFU9VnVVVVVSSSSSSntyts
""".strip().splitlines()


EYES = ((39, 20), (47, 20))
EYE_WHITE = (221, 211, 188)
PUPIL = (28, 20, 17)


def make_frame(glance=0):
    pixels = [[PALETTE[SYMBOLS.index(c)] for c in row] for row in MEME]
    for x, y in EYES:
        for dx in range(1, 4):
            pixels[y][x + dx] = EYE_WHITE
        for dx in range(5):
            pixels[y + 1][x + dx] = EYE_WHITE
        pupil_x = x + 2 + glance
        pixels[y][pupil_x] = PUPIL
        pixels[y + 1][pupil_x] = PUPIL
    lines = []
    for y in range(0, len(pixels), 2):
        parts = []
        for top, bottom in zip(pixels[y], pixels[y + 1]):
            r, g, b = top
            br, bg, bb = bottom
            parts.append(f"\033[38;2;{r};{g};{b}m\033[48;2;{br};{bg};{bb}m▀")
        lines.append("".join(parts) + "\033[0m")
    return "\n".join(lines)


def animate_art(seconds=8):
    """Play for 8 seconds and return. Use seconds=None to loop until Ctrl+C."""
    frames = {direction: make_frame(direction) for direction in (-1, 0, 1)}
    if not sys.stdout.isatty():
        print(frames[0])
        return
    height = len(MEME) // 2
    # Reserve space, then return to its top so frames do not scroll.
    sys.stdout.write("\n" * height + f"\033[{height}A\r\0337\033[?25l")
    sys.stdout.flush()
    start = time.monotonic()
    sequence = ((0, 1.2), (-1, 0.8), (0, 0.3), (1, 0.8), (0, 1.2))
    try:
        while seconds is None or time.monotonic() - start < seconds:
            for direction, delay in sequence:
                sys.stdout.write("\0338" + frames[direction])
                sys.stdout.flush()
                if seconds is not None:
                    remaining = seconds - (time.monotonic() - start)
                    if remaining <= 0:
                        return
                    delay = min(delay, remaining)
                time.sleep(delay)
    except KeyboardInterrupt:
        pass
    finally:
        sys.stdout.write("\0338" + frames[0] + "\033[0m\033[?25h\n")
        sys.stdout.flush()
        
if __name__ == "__whodey.py__":
    animate_art()

animate_art()
