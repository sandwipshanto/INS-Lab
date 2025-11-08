import re
from collections import Counter

# English letter frequencies
ENGLISH_FREQ = {
    'e': 12.22, 't': 9.67, 'a': 8.05, 'o': 7.63, 'i': 6.28,
    'n': 6.95, 's': 6.02, 'h': 6.62, 'r': 5.29, 'd': 5.10,
    'l': 4.08, 'c': 2.23, 'u': 2.92, 'm': 2.33, 'w': 2.60,
    'f': 2.14, 'g': 2.30, 'y': 2.04, 'p': 1.66, 'b': 1.67,
    'v': 0.82, 'k': 0.95, 'j': 0.19, 'x': 0.11, 'q': 0.06, 'z': 0.06
}

def analyze_frequency(ciphertext):
    """Analyze character frequency in the ciphertext."""
    letters = re.findall(r'[a-z]', ciphertext.lower())
    total = len(letters)
    freq_count = Counter(letters)
    freq_percent = {char: (count / total) * 100 for char, count in freq_count.items()}
    return sorted(freq_percent.items(), key=lambda x: x[1], reverse=True)

def create_substitution_map(sorted_freq):
    """Create substitution map based on frequency."""
    english_sorted = sorted(ENGLISH_FREQ.items(), key=lambda x: x[1], reverse=True)
    sub_map = {}
    for i, (cipher_char, _) in enumerate(sorted_freq[:26]):
        if i < len(english_sorted):
            sub_map[cipher_char] = english_sorted[i][0]
    return sub_map

def decrypt(ciphertext, sub_map):
    """Decrypt ciphertext using substitution map."""
    plaintext = ""
    for char in ciphertext:
        if char.lower() in sub_map:
            decrypted = sub_map[char.lower()]
            plaintext += decrypted.upper() if char.isupper() else decrypted
        else:
            plaintext += char
    return plaintext

def break_substitution(ciphertext, cipher_name):
    """Break substitution cipher using frequency analysis."""
    print(f"\n{cipher_name}:")
    print("-" * 60)
    
    # Frequency analysis
    sorted_freq = analyze_frequency(ciphertext)
    
    print("Top 10 most frequent letters in cipher:")
    for char, percent in sorted_freq[:10]:
        print(f"{char}: {percent:.2f}%", end="  ")
    print("\n")
    
    # Create and apply substitution map
    sub_map = create_substitution_map(sorted_freq)
    plaintext = decrypt(ciphertext, sub_map)
    
    print("Initial decryption (first 300 chars):")
    print(plaintext[:300] + "...")
    
    return plaintext


# Cipher texts
cipher1 = """af p xpkcaqvnpk pfg, af ipqe qpri, gauuikifc tpw, ceiri udvk tiki afgarxifrphni cd eao-
-wvmd popkwn, hiqpvri du ear jvaql vfgikrcpfgafm du cei xkafqaxnir du xrwqedearcdkw pfg
du ear aopmafpcasi xkdhafmr afcd fit pkipr. ac tpr qdoudkcafm cd lfdt cepc au pfwceafm
epxxifig cd ringdf eaorinu hiudki cei opceiopcaqr du cei uaing qdvng hi qdoxnicinw tdklig dvc-
-pfg edt rndtnw ac xkdqiigig, pfg edt odvfcpafdvr cei dhrcpqnir--ceiki tdvng pc niprc kiopaf dfi
mddg oafg cepc tdvng qdfcafvi cei kiripkqe"""

cipher2 = """aceah toz puvg vcdl omj puvg yudqecov, omj loj auum klu thmjuv hs klu zlcvu shv
zcbkg guovz, upuv zcmdu lcz vuwovroaeu jczoyyuovomdu omj qmubyudkuj vukqvm. klu
vcdluz lu loj avhqnlk aodr svhw lcz kvopuez loj mht audhwu o ehdoe eunumj, omj ck toz
yhyqeoveg auecupuj, tlokupuv klu hej sher wcnlk zog, klok klu lcee ok aon umj toz sqee hs
kqmmuez zkqssuj tckl kvuozqvu. omj cs klok toz mhk umhqnl shv sowu, kluvu toz oezh lcz
yvhehmnuj pcnhqv kh wovpue ok. kcwu thvu hm, aqk ck zuuwuj kh lopu eckkeu ussudk hm
wv. aonncmz. ok mcmukg lu toz wqdl klu zowu oz ok scskg. ok mcmukg-mcmu klug aunom kh
doee lcw tuee-yvuzuvpuj; aqk qmdlomnuj thqej lopu auum muovuv klu wovr. kluvu tuvu zhwu
klok zlhhr klucv luojz omj klhqnlk klcz toz khh wqdl hs o nhhj klcmn; ck zuuwuj qmsocv klok
omghmu zlhqej yhzzuzz (oyyovumkeg) yuvyukqoe ghqkl oz tuee oz (vuyqkujeg)
cmubloqzkcaeu tuoekl. ck tcee lopu kh au yocj shv, klug zocj. ck czm'k mokqvoe, omj kvhqaeu
tcee dhwu hs ck! aqk zh sov kvhqaeu loj mhk dhwu; omj oz wv. aonncmz toz numuvhqz tckl
lcz whmug, whzk yuhyeu tuvu tceecmn kh shvncpu lcw lcz hjjckcuz omj lcz nhhj shvkqmu. lu
vuwocmuj hm pczckcmn kuvwz tckl lcz vueokcpuz (ubduyk, hs dhqvzu, klu zodrpceeu-
aonncmzuz), omj lu loj womg juphkuj ojwcvuvz owhmn klu lhaackz hs yhhv omj
qmcwyhvkomk sowcecuz. aqk lu loj mh dehzu svcumjz, qmkce zhwu hs lcz ghqmnuv dhqzcmz
aunom kh nvht qy. klu uejuzk hs kluzu, omj aceah'z sophqvcku, toz ghqmn svhjh aonncmz.
tlum aceah toz mcmukg-mcmu lu ojhykuj svhjh oz lcz lucv, omj avhqnlk lcw kh ecpu ok aon
umj; omj klu lhyuz hs klu zodrpceeu- aonncmzuz tuvu scmoeeg jozluj. aceah omj svhjh
loyyumuj kh lopu klu zowu acvkljog, zuykuwauv 22mj. ghq loj aukkuv dhwu omj ecpu luvu,
svhjh wg eoj, zocj aceah hmu jog; omj klum tu dom dueuavoku hqv acvkljog-yovkcuz
dhwshvkoaeg khnukluv. ok klok kcwu svhjh toz zkcee cm lcz ktuumz, oz klu lhaackz doeeuj klu
cvvuzyhmzcaeu ktumkcuz auktuum dlcejlhhj omj dhwcmn hs onu ok klcvkg-klvuu"""

# Main execution

break_substitution(cipher1, "Cipher-1")
break_substitution(cipher2, "Cipher-2")

