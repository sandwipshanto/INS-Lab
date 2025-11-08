def decrypt(ciphertext, sub_map):
    plaintext = ""
    for char in ciphertext:
        if char.lower() in sub_map:
            decrypted = sub_map[char.lower()]
            plaintext += decrypted.upper() if char.isupper() else decrypted
        else:
            plaintext += char
    return plaintext

# Correct mappings (discovered through manual analysis)
cipher1_map = {
    'a': 'i', 'b': 'b', 'c': 't', 'd': 'o', 'e': 'h', 'f': 'n',
    'g': 'f', 'h': 'b', 'i': 'e', 'j': 'q', 'k': 'r', 'l': 'k',
    'm': 'm', 'n': 'l', 'o': 'm', 'p': 'a', 'q': 'c', 'r': 's',
    't': 'w', 'u': 'f', 'v': 'u', 'w': 'y', 'x': 'p', 'y': 'y', 'z': 'v'
}

cipher2_map = {
    'a': 'b', 'b': 'b', 'c': 'i', 'd': 'c', 'e': 'l', 'g': 'y',
    'h': 'f', 'j': 'd', 'k': 't', 'l': 'h', 'm': 'n', 'o': 'a',
    'q': 'x', 's': 'f', 't': 'w', 'u': 'e', 'v': 'r', 'w': 'm', 'y': 'p', 'z': 's'
}

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

# Decrypt
print("CIPHER-1 DECRYPTED:")
print(decrypt(cipher1, cipher1_map))

print("\n" + "="*60 + "\n")

print("CIPHER-2 DECRYPTED:")
print(decrypt(cipher2, cipher2_map))
