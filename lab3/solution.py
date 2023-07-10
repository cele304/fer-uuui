import sys
import csv
import collections
import math

#izračun entropije razreda
def entropijaKlase(br_klase, oznaka_broja_klase):
    if oznaka_broja_klase == 0: #ako je, nema primjera u klasi koji pripadaju nekoj vrijednosti
        return 0
    vjerojatnost = oznaka_broja_klase / br_klase #vjerojatnost da će primjer pripadati klasi
    return - vjerojatnost * math.log2(vjerojatnost)

#izračun entropije značajke
def entropijaZnacajke(vrijZnacajke, oznaka, listaKlasa):
    entropija = 0
    for c in listaKlasa: #za svaku vrijednost klase u listi klasa izračunava se broj primjera koji pripada toj klasi
        oznaka_broja_klase = brojRedova(vrijZnacajke, oznaka, c)
        entropija += entropijaKlase(len(vrijZnacajke), oznaka_broja_klase) #rezultat se dodaje na ukupnu entropiju
    return entropija

#pomoću ukupnog broja primjera u skupu podataka i ukupnog broja različitih vrijednosti klase izračunava ukupnu entropiju svake klase
def ukupnaEntropijaKlase(ukupniBrojRedova, ukupniBrojRazreda):
    return - (ukupniBrojRazreda / ukupniBrojRedova) * math.log2(ukupniBrojRazreda / ukupniBrojRedova)

#izračun ukupne entropije cijelog skupa podataka
def ukupnaEntropija(train_podaci, oznaka, listaKlasa):
    ukBrRedova = len(train_podaci)
    ukEntropija = 0
    for c in listaKlasa:
        ukBrRazreda = brojRedova(train_podaci, oznaka, c)
        ukEntropija += ukupnaEntropijaKlase(ukBrRedova, ukBrRazreda)
    return ukEntropija

#izračunava broj redova u skupu podataka u kojima se vrijednost u stupcu s oznakom oznaka podudara s vrijednošću vrij
def brojRedova(podaci, oznaka, vrij):
    return sum(1 for ind in podaci.index if podaci.at[ind, oznaka] == vrij) #iteriranje kroz redove skupa podataka i provjera podudara li se vrijednost u stupcu oznaka s traženom vrijednošću vrij

#služi za izračunavanje broja različitih vrijednosti za svaku značajku u skupu podataka
def brVrijednostiZnacajki(imeZnacajke, train_podaci):
    brVrijednostiZnacajkiDict = {}
    for vrij in train_podaci[imeZnacajke]: #prolazi kroz sve primjere u skupu podataka i provjerava različite vrijednosti
        if vrij in brVrijednostiZnacajkiDict:
            brVrijednostiZnacajkiDict[vrij] += 1 #za svaku vrijednost pohranjuje broj pojavljivanja u rječnik brVrijednostiZnacajki
        else:
            brVrijednostiZnacajkiDict[vrij] = 1
    return brVrijednostiZnacajkiDict

#računa IG određene značajke u skupu podataka za treniranje pomoću oznake i liste razreda
def informacijskaDobit(imeZnacajke, train_podaci, oznaka, listaKlasa):
    brVrijednostiZnacajkiDict = brVrijednostiZnacajki(imeZnacajke, train_podaci) #prvo računamo broj pojavljivanja svake vrijednosti značajke u ukupan broj redova u skupu za treniranje
    ukBrRedova = len(train_podaci)
    znacajkaIG = 0.0

    for znacajka, znacajkaBrVrij in brVrijednostiZnacajkiDict.items(): #za svaku vrijednost značajke stvaramo novi skup podataka sa vrijednostima značajke
        vrijZnacajke = train_podaci[train_podaci[imeZnacajke] == znacajka] #računamo entropiju značajke i vjerojatnost pojave te vrijednosti značajke u skupu podataka
        znacajkaVrijEntropija = entropijaZnacajke(vrijZnacajke, oznaka, listaKlasa)
        znacajkaVjerojatnost = znacajkaBrVrij / ukBrRedova
        znacajkaIG += znacajkaVjerojatnost * znacajkaVrijEntropija #na kraju računamo IG kao razliku ukupne entropije skupa za treniranje i doprinosa svake vrijednosti značajke

    return ukupnaEntropija(train_podaci, oznaka, listaKlasa) - znacajkaIG

#funkcija za izračunavanje najinformiranije značajke
def najinformativnijaZnacajka(train_podaci, oznaka, listaKlasa):
    listaZnacajki = []
    #prolazimo kroz sve stupce u skupu podataka provjeravamo je li ime stupca jednako oznaci, ako nije dodajemo u listu značajki
    listaZnacajki = [stupac for stupac in train_podaci if stupac != oznaka] 
    maxIG = -1
    najinformiranija = None

    for znacajka in listaZnacajki:  # za svaku znacajku u skupu podataka
        znacajkaIG = informacijskaDobit(znacajka, train_podaci, oznaka, listaKlasa) #izračunavamo njenu IG
        if maxIG < znacajkaIG:  # oznaka znacajke sa najvecom informacijskom dobiti
            maxIG = znacajkaIG
            najinformiranija = znacajka

    return najinformiranija

#odreduje vrijednost koja će biti dodijeljena čvoru u stablu odlučivanja na temelju broja redova u skupu podataka za svaku vrijednost iz liste razreda
def dodijeliVrijednostCvoru(vrijZnacajke, oznaka, listaKlasa):
    for c in listaKlasa: #prolazimo kroz sve vrijednosti u listi razreda i provjeravamo broj redova u skupu podataka
        brRazreda = len(vrijZnacajke[vrijZnacajke[oznaka] == c])
        if brRazreda == len(vrijZnacajke):  #ako je broj redova za neku vrijednost jednak ukupnom broju redova u skupu podataka
            #tada je ta vrijednost jedinstveni razred za te podatke i vraća se kao vrijednost čvora u stablu
            return c
    return "?"  #inače označi nepoznatu vrijednost čvora

#funkcija generira podstablo odluke za zadano svojstvo na temelju skupa podataka i liste mogućih oznaka razreda
def generirajPodstablo(imeZnacajke, train_podaci, oznaka, listaKlasa):
    brVrijednostiZnacajkiDict = brVrijednostiZnacajki(imeZnacajke, train_podaci) #izračunavamo broj vrijednosti značajki u skupu podataka i stvaramo rječnik stablo
    stablo = {}
    for znacajka, count in brVrijednostiZnacajkiDict.items(): #prolazi se kroz svaku vrijednost značajke i stvara se podstabla za svaku vrijednost
        vrijZnacajke = train_podaci[train_podaci[imeZnacajke] == znacajka]
        dodjeljen = False
        cvorOznaka = dodijeliVrijednostCvoru(vrijZnacajke, oznaka, listaKlasa) #ako se na osnovu određene vrijednosti svojstva može dodijeliti oznaka razreda,
        if cvorOznaka != "?":
            stablo[znacajka] = cvorOznaka #tada se ta vrijednost i oznaka razreda dodaju u stablo i ta vrijednost se izbaci iz daljnjeg razmatranja
            train_podaci = train_podaci[train_podaci[imeZnacajke] != znacajka]
            dodjeljen = True
        if not dodjeljen:   #inače dodaje se u stablo, ali s oznakom "?" koja označava da se daljnja odluka mora donijeti na temelju drugih svojstava
            stablo[znacajka] = "?"
    return stablo, train_podaci #na kraju vraćamo stablo i preostali skup podataka koji nije dodijeljen u stablo


#funkcija gradi stablo odluke rekurzivno
#započinje iz korijena stabla koji se prosljeđuje kao argument korijen
def napraviStablo(korijen, prethodnaVrijednost, train_podaci, oznaka, listaKlasa):
    if len(train_podaci) != 0:  #prvo provjerava da li je skup podataka prazan, a ako nije, određuje najinformativniju značajku
        najinformiranija = najinformativnijaZnacajka(train_podaci, oznaka, listaKlasa)
        stablo, train_podaci = generirajPodstablo(najinformiranija, train_podaci, oznaka, listaKlasa)  #generira podstablo za tu značajku i ažurira skup podataka
        iduciKorijen = None

        if prethodnaVrijednost != None: #prima tu prethodnu vrijednost, koja se koristi ako se stablo gradi na više razina, a ne samo na jednoj
            korijen[prethodnaVrijednost] = dict()   #stvara se čvor za trenutnu značajku u stablu
            korijen[prethodnaVrijednost][najinformiranija] = stablo
            iduciKorijen = korijen[prethodnaVrijednost][najinformiranija]#ako trenutna vrijednost prethodnog čvora nije none, stablo se dodaje kao podstabla tog čvora
        else:  #inače stablo se dodaje kao podstablo korijena stabla.
            korijen[najinformiranija] = stablo
            iduciKorijen = korijen[najinformiranija]

        for cvor, grana in list(iduciKorijen.items()):  #iteriramo kroz stablo
            if grana == "?":
                vrijZnacajke = train_podaci[train_podaci[najinformiranija] == cvor]  #novi azurirani skup podataka 
                napraviStablo(iduciKorijen, cvor, vrijZnacajke, oznaka, listaKlasa)
                #nakon stvaranja podstabla, funkcija se rekurzivno poziva za svaki čvor koji sadrži "?", koristeći novi skup podataka koji je ažuriran za trenutnu značajku
                #to se radi sve dok skup podataka postane prazan ili se sve grane u stablu ne mogu dalje proširiti
    return stablo  #vraćamo stablo

#izgrađujemo stablo odluke
def id3(train_podaci, oznaka):
    unique_classes = set(train_podaci[oznaka])  # dobivanje jedinstvenih vrijednosti stupca s oznakom oznaka pomoću set funkcije
    listaKlasa = list(unique_classes)           # pretvaranje seta natrag u listu pomoću list funkcije
    stablo = napraviStablo(train_podaci, oznaka, listaKlasa) #zovemo funkciju napravi stablo koja izgrađuje stablo kojeg vraćamo
    return stablo


#funkcija služi za predviđanje klase na temelju stabla odluke
def predict(stablo, cvor):
    if not isinstance(stablo, dict):  #ovo je za onaj primjer samo sa yes
        return stablo  #ako je stablo list vraća stablo
    else:
        korijen = next(iter(stablo))  #inače traži ime korijena i vrijednosti koju primjer ima za tu značajku
        znacajka = cvor[korijen]
        if znacajka in stablo[korijen]:  #ako je vrijednost značajke u trenutnom čvoru stabla, funkcija se poziva rekurzivno
            return predict(stablo[korijen][znacajka], cvor) #ovaj puta s čvorom djetetom koji je vrijednost značajke
        else:
            #ako su sve znacajke jednako ceste, vrati onu po abecednom poretku
            oznake = list(stablo[korijen].keys())
            if len(set(stablo[korijen].values())) == 1:
                return sorted(oznake)[0] #to se radi sve dok se ne dosegne list
            else:
                brOznaka = collections.Counter(stablo[korijen].values())  #ovo je za onaj primjer sa matricom 100 100 100
                najcesca = brOznaka.most_common()[-1][0]
                return najcesca

#funkcija za određivanje matrice zabune
def confusion_matrix(stvarno, predvideno):
    razredi = sorted(set(stvarno)) #dobivanje sortirane liste jedinstvenih razreda
    num_razredi = len(set(stvarno)) #izračunavanje broja jedinstvenih razreda
    
    matrica = [] #stvaranje prazne matrice
    for i in range(num_razredi):
        row = [0] * num_razredi
        matrica.append(row)

    for i in range(len(stvarno)):  #iteriranje kroz stvarne i predviđene klase
        tocniInd = razredi.index(stvarno[i]) #pronalaženje indeksa stvarne klase u listi sortiranih klasa
        predvideniInd = razredi.index(predvideno[i]) #pronalaženje indeksa predviđene klase u listi sortiranih klasa
        matrica[tocniInd][predvideniInd] += 1 #dodavanje broja primjera u odgovarajući element matrice
        
    return matrica


#funkcija u kojoj se poziva funkcija za predviđanje pomoću koje se računa accuracy i confusion matrix
def evaluate(stablo, testPodaci, oznaka):
    tocno, krivo, predvideno, stvarno = 0, 0, [], []
    for ind, red in testPodaci.iterrows():  #za svaki red u skupu podataka
        redDict = dict(red)  #pretvori red u rjecnik
        rez = predict(stablo, redDict)  #predvidi rezultat
        predvideno.append(rez) #spremi rezultat 
        stvarno.append(red[oznaka])
        if rez == stvarno[-1]:  #usporedi predviđenu i stvarnu vrijednost
            tocno += 1
        else:
            krivo += 1
    accuracy = tocno / (tocno + krivo)  #izračunaj accuracy
    cm = confusion_matrix(stvarno, predvideno) #izračunaj cm
    return accuracy, predvideno, cm



#############################################
# 2 dio - sa hiperparametrom max_depth
def generirajPodstablo(imeZnacajke, train_podaci, oznaka, listaKlasa, dubina, prethodnaVrijednost=None):
    if prethodnaVrijednost is not None: #prvo provjerava je li prethodna vrijednost definirana i filtrira podatke prema njoj ako je
        train_podaci = train_podaci[train_podaci[prethodnaVrijednost] == imeZnacajke]
        
    brVrijednostiZnacajkiDict = train_podaci[imeZnacajke].value_counts(sort=False)
    stablo = {} #računa broj pojavljivanja svake vrijednosti atributa imeZnacajke u skupu podataka

    for znacajka in brVrijednostiZnacajkiDict.index: #prolazi kroz sve vrijednosti i stvara grananja stabla
        br = brVrijednostiZnacajkiDict[znacajka]
        vrijZnacajke = train_podaci[train_podaci[imeZnacajke] == znacajka]
        
        dodjeljen = False #je li stablu dodjeljena klasa za trenutnu vrijednost značajke
        for c in listaKlasa: #prolazimo kroz sve klase iz liste listaklasa
            brRazreda = len(vrijZnacajke[vrijZnacajke[oznaka] == c]) #za svaku c broji se broj retka u vrijZnacajke koji ima oznaku oznaka jednaku c
            if brRazreda == br: #ako je taj broj jednak broju pojavljivanja br, to znači da su svi retci s vrijednošću imeZnacajke jednaku znacajka označeni klasom c
                stablo[znacajka] = c #stablo se ažurira tako da se za vrijednost znacajka postavi c
                dodjeljen = True #i varijabla dodjeljen na true

        if not dodjeljen: #ako nijedna klasa nije dodjeljena provjerava se dubina stabla
            if dubina == 0: #ako je dubina 0, postavlja se klasa koja je najčešća u tom podskupu kao oznaka lista
                klase = train_podaci[oznaka].values.tolist()
                najcesciRazred = Counter(klase).most_common(1)[0][0]
                stablo[znacajka] = najcesciRazred
            else: #ako nije 0, poziva se napravi stablo koja generira podstablo za podskup podataka i smanjuje dubinu za 1
                podstablo, _ = napraviStablo(vrijZnacajke, oznaka, listaKlasa, dubina=dubina - 1)
                stablo[znacajka] = podstablo

    return stablo, train_podaci #vraća stablo i skup podataka za treniranje koji su filtrirani prema trenutnoj vrijednosti atributa



def napraviStablo(train_podaci, oznaka, listaKlasa, prethodnaVrijednost=None, dubina=None):
    if len(train_podaci) == 0: #ako je broj primjera u skupu podataka 0, ne mogu se izgraditi daljnji čvorovi
        najcesciRazred = listaKlasa[0] #pa se list čvora postavlja kao najzastupljenija vrijednost ciljne varijable u skupu podataka
        return najcesciRazred, train_podaci

    if len(listaKlasa) == 1: #ako postoji samo jedna moguća vrijednost ciljne varijable u preostalom skupu podataka
        return listaKlasa[0], train_podaci #tada se ta vrij koristi kao list čvora

    if dubina == 0: #ako je dostignuta maxdubina stabla, tada se na ovom čvoru postavlja najzastupljenija vrij ciljne varijable
        klase = train_podaci[oznaka].values.tolist()
        najcesciRazred = collections.Counter(klase).most_common(1)[0][0]
        return najcesciRazred, train_podaci

    najinformiranija = najinformativnijaZnacajka(train_podaci, oznaka, listaKlasa) #inače se određuje najinformativnija značajka i generira se podstablo za trenutnu značajku
    stablo, train_podaci = generirajPodstablo(najinformiranija, train_podaci, oznaka, listaKlasa, dubina, prethodnaVrijednost) #za svaki čvor u stablu koji ima daljnje grane poziva se rekurzivno funkcija napravi stablo

    if prethodnaVrijednost is not None: #ako je definirana prethodna vrijednost, stvara se korijen stabla koji sadrži prethodnu vrijednost i podstablo za najinformativniju značajku
        korijen = {prethodnaVrijednost: {najinformiranija: stablo}}
    else: #inače korijen stabla sadrži samo podstablo za najinformativniju značajku
        korijen = {najinformiranija: stablo}

    for cvor, grana in list(stablo.items()):
        if isinstance(grana, dict): #za svaki čvor u stablu koji ima daljnje grane, rekurzivno se poziva funkcija napravistablo kako bi se generiralo podstablo za taj čvor 
            podstablo, _ = napraviStablo(train_podaci[train_podaci[najinformiranija] == cvor], oznaka, listaKlasa, prethodnaVrijednost=najinformiranija, dubina=dubina - 1)
            if cvor not in korijen: #rekurzivni pozivi se vrše za podskupove podataka koji odgovaraju pojedinim granama
                korijen[cvor] = {}
            korijen[cvor][najinformiranija] = podstablo

    return korijen, train_podaci #funkcija vraća korijen stabla i filtrirani skup podataka


def id3(train_podaci, oznaka, max_dubina=None): #isto kao i gore samo sa maxdubina
    unique_razredi = set(train_podaci[oznaka])  # dobivanje jedinstvenih vrijednosti stupca s oznakom oznaka pomoću set() funkcije
    lista_razreda = list(unique_razredi)        # pretvaranje seta natrag u listu pomoću list() funkcije

    if max_dubina is None:
        max_dubina = float('inf')

    stablo, _ = napraviStablo(train_podaci, oznaka, lista_razreda, dubina=max_dubina)
    return stablo


#######################################################
#funkcije za print i glavni dio programa
#ispis stabla odluke
def print_stablo(stablo, dubina=1, prefiks=""):
    if not isinstance(stablo, dict):  #ovo je za onaj primjer koji samo printa yes kao granu
        print(stablo) #provjerava se je li stablo rjecnik
        return #ako nije imamo samo list i funkcija se prekida
    for kljuc, vrij in stablo.items(): #prolazi se kroz ključeve i vrijednosti u stablu
        if isinstance(vrij, dict): #provjerava se je li vrijednost čvora također rječnik, ako je postoji daljnje grananje
            for pod_kljuc, pod_vrij in vrij.items(): #stvara se novi prefiks za formatiranje ispisa
                novi_prefiks = f"{prefiks}{dubina}:{kljuc}={pod_kljuc} " #prefiks od trenutne dubine čvora, ključa i vrijednosti podstabla
                if isinstance(pod_vrij, dict): #provjerava se je li vrijednost podvrij također rječnik
                    print_stablo(pod_vrij, dubina=dubina + 1, prefiks=novi_prefiks) #ako je rekurzivno se poziva funkcija printstablo za to podstablo s povećanom dubinom i novim prefiksom
                else:
                    print(f"{prefiks}{dubina}:{kljuc}={pod_kljuc} {pod_vrij}") #inače je to list 
        else:
            print(f"{prefiks}{dubina}:{kljuc} {vrij}") #također list

#ispis accuracy
def print_accuracy(accuracy):
    accuracy_formatirano = "{:.5f}".format(round(accuracy, 5)) #zaokruzi na 5 decimala
    print("[ACCURACY]:", accuracy_formatirano)

#ispis predictions
def print_predictions(predictions):
    predictions_str = []  # prazna lista za spremanje stringova
    for p in predictions:  # iteriranje kroz listu predikcija
        p_str = str(p)  # pretvaranje pojedine predikcije u string
        predictions_str.append(p_str)  # dodavanje stringa u listu predictions_str
    print('[PREDICTIONS]:', ' '.join(predictions_str))  # ispis liste predictions_str

#ispis confusion matrix
def print_confusion_matrix(cm):
    print('[CONFUSION_MATRIX]:')
    for red in cm:
        print(*red, sep=' ')





import pandas as pd

trainPodaci = pd.read_csv(sys.argv[1])  #skup podataka za treniranje
ciljna_varijabla_train = trainPodaci.columns[-1].split()[-1]  # ciljna varijabla je zadnja rijec prvog retka
testPodaci = pd.read_csv(sys.argv[2])  #skup podataka za testiranje
ciljna_varijabla_test = testPodaci.columns[-1].split()[-1]  # ciljna varijabla je zadnja rijec prvog retka

if len(sys.argv) == 3:
    stablo = id3(trainPodaci, ciljna_varijabla_train)
    print('[BRANCHES]:')  # ovo ne može u print_stablo zbog rekurzije
    print_stablo(stablo, prefiks="")

    accuracy, predictions, cm = evaluate(stablo, testPodaci, ciljna_varijabla_test)  # primjeni predviđanje ciljne varijable
    print_accuracy(accuracy)
    print_predictions(predictions)
    print_confusion_matrix(cm)

if len(sys.argv) == 4:
    max_dubina = int(sys.argv[3])

    stablo = id3(trainPodaci, ciljna_varijabla_train, max_dubina)
    print('[BRANCHES]:')    # ovo ne može u print_stablo zbog rekurzije
    print_stablo(stablo, prefiks="")

    accuracy, predictions, cm = evaluate(stablo, testPodaci, ciljna_varijabla_test)  # primjeni predviđanje ciljne varijable
    print_accuracy(accuracy)
    print_predictions(predictions)
    print_confusion_matrix(cm)

##################################################################################
