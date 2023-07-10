import numpy as np
import sys
import random
import time
import warnings

#inicijalizira matricu tezina u mrezi
def inicijalizirajTezine(dimenzije):
    #mreza se sastoji od slojeva, a dimenzije su broj neurona u svakom sloju
    matricaTezina = [
        np.random.normal(loc=0.0, scale=0.01, size=(dimenzije[i], dimenzije[i+1])) #u for petlji prolazimo kroz sve slojeve osim zadnjeg(nema tezine jer je izlazni sloj)
        for i in range(len(dimenzije) - 1) #za svaki sloj generiramo matricu tezina i generiramo slucajne vrijednosti iz normalne distribucije
    ]
    return matricaTezina #na kraju vracamo listu sa svim matricama tezina izmedu svakog para slojeva


#inicijalizira pomake u mreži
#pomak je konstantna vrijednost koja se dodaje izlazu neurona
def inicijalizirajPomake(dimenzije):
    pomaci = [
        np.random.normal(loc=0.0, scale=0.01, size=dimenzije[i+1]) #generiraju se slučajne vrijednosti za pomake, kroz for petlju prolazimo kroz sve slojeve osim ulaznog
        for i in range(len(dimenzije) - 1) #za svaki sloj generiramo pomake, dimenzija pomaka odgovara broju neurona u sljedećem sloju
    ]
    return pomaci

#funkcija služi za izgradnju mreže i izvođenje unaprijednog prolaza kroz mrežu
def izgradiMrezu(podaci, cilj, dimenzije): #inicijaliziramo vrijednosti težina i pomaka
    matricaTezina = inicijalizirajTezine(dimenzije) 
    pomaci = inicijalizirajPomake(dimenzije) 
    rez = unaprijedniProlaz(podaci, cilj, matricaTezina, pomaci) #nakon toga provodimo unaprijedni prolaz kroz mrežu koristeći težine i pomake
    #unaprijedni prolaz se sastoji od propagacije ulaznih podataka kroz slojeve mreže sve do izlaznog sloja
    return rez


#sigmoidalna funkcija je aktivacijska funkcija u neuronskim mrežama
#ako je vrijednost elementa u nizu >=0 pozitivni dio sigmoide(-x), inače negativni(x), neprekidna i diferencijabilna pa je pogodna kao aktivacijska funkcija
def sigmoida(x):
    return np.where(x >= 0, 1 / (1 + np.exp(-x)), np.exp(x) / (1 + np.exp(x))) #inace je bio overflow warning(i sad bude ponekad)


#mse između dva skupa vrijednosti
#srednju vrijednost svih kvadratnih razlika točnih i predviđenih vrijednosti
def srednjaKvadratnaPogreska(tocno, predvideno):
    return np.mean((tocno - predvideno) ** 2)


#funkcija računa skalarni umnožak između težina, ulaza i pomaka
def skalarniUmnozak(tezine, ulazi, pomaci):
    skalarni = np.dot(tezine.T, ulazi) + pomaci[:, np.newaxis] #matrično množenje transponirane matrice težina i vektora ulaza, dodaje se pomak na svaki skalarni umnožak
    return skalarni    #koristeći newaxis vektor pomaka proširuje se dodavanjem nove osi kako bi se izvršilo pravilno dodavanje pomaka na svaki skalarni umnožak


#funkcija provodi feedforward kroz mrežu
def primjeniUnaprijedniProlaz(ulazi, matricaTezina, pomaci):
    trenutniUlaz = ulazi.T #transponiramo ulazne podatke zbog skalarnog umnoška

    for tezineRazina, pomaciRazina in zip(matricaTezina, pomaci): #prolazi se kroz svaki sloj mreže računa se skalarni umnožak kao linearna kombinacija ulaza u svakom neuronu sloja
        skalarni = skalarniUmnozak(tezineRazina, trenutniUlaz, pomaciRazina)
        trenutniUlaz = sigmoida(skalarni) if tezineRazina is not matricaTezina[-1] else skalarni #provodi se aktivacija neurona pozivanjem funkcije sigmoida
        #ako je sloj zadnji, onda se aktivacija ne provodi, nego se koristi samo skalarni umnožak
        #nakon što se izračuna aktivacija za trenutni sloj, rezultat se postavlja kao trenutni ulaz za sljedeću iteraciju petlje
    return trenutniUlaz  #vraća se posljednji trenutni ulaz tj. izlaz mreže



#provodi se forwardpropagation pomoću ulaznih podataka, ciljnih vrijednosti, matrice težina i pomaka
def unaprijedniProlaz(podaci, cilj, matricaTezina, pomaci):
    cilj = cilj.astype(float)  #prvo konvertiramo ciljni vektor u float kako bismo uskladili tipove podataka
    trenutniIzlaz = primjeniUnaprijedniProlaz(podaci, matricaTezina, pomaci)
    mse = srednjaKvadratnaPogreska(cilj, trenutniIzlaz)  #provodimo feedforward iz prethodne funkcije i računamo srednju kvadratnu pogrešku
    return mse, matricaTezina, pomaci #na kraju vraćamo pogrešku, matricu težina i pomake




#izracunavamo fitness vrijednost za svaku jedinku i vraćamo inverznu vrijednost fitnessa kao rezultat
def izracunajFitness(populacija):
    #izdvajamo fitness iz svake jedinke u populaciji(prva komponenta)
    #pretvaramo vrijednosti u numpy niz
    return 1 / np.asarray([jedinka[0] for jedinka in populacija]) #vraćamo recipročnu vrijednost fitnessa jer želimo maksimizirati fitness



#izracunavamo vjerojatnosti selekcije za svaku jedinku na temelju fitness vrijednosti
def izracunajVjerojatnosti(fitnessVrij):
    fitnessUkupno = np.sum(fitnessVrij) #sumiramo sve inverzne fitnesse
    return fitnessVrij / fitnessUkupno #računamo vjerojatnost selekcije za svaku jedinku dijeljenjem inverznih vrijednosti fitnessa sa ukupnim zbrojem, #veća vrij fitnessa ima veću vjv odabira



#sluzi za odabir roditelja iz populacije na temelju vjerojatnosti selekcije
def birajRoditelje(populacija, vjerojatnosti):
    roditeljIndeksi = np.random.choice(range(len(populacija)), size=2, p=vjerojatnosti) #pomocu slucajnog odabira generiramo indekse 2 roditelja iz populacije, jedinke s većom vjv imaju veću šansu za biti odabrane
    return [populacija[ind][1:] for ind in roditeljIndeksi] #izdvaja iz populacije samo informacije o roditeljima tako što prolazimo kroz indekse roditelja i izdvajamo elemente jedinke nakon prvog elementa




def napraviIducuGeneraciju(populacija, elitizam, p, K):
    iducaGeneracija = [] #generira iduću generaciju jedinki u genetskom algoritmu

    elitni = primjeniElitizam(populacija, elitizam) #biramo elitne jedinke iz trenutne populacije tako da se iz trenutne generacije izdvaja genetska informacija svake elitne jedinke
    iducaGeneracija.extend([(jedinka[1], jedinka[2]) for jedinka in elitni]) #dodaje se u listu pomoću extend

    while len(iducaGeneracija) < len(populacija): #sve dok iduća generacija ne dostigne željeni broj jedinki(isti kao u trenutnoj populaciji)
        potomak = krizanje(populacija) #vršimo križanje jedinki iz trenutne populacije i potomak se dodaje u iduću generaciju
        iducaGeneracija.append(potomak)

    mutiranaIducaGeneracija = mutiraj(iducaGeneracija, p, K) #nakon što imamo dovoljan broj potomaka mutiramo sve jedinke u idućoj generaciji

    return mutiranaIducaGeneracija


#krizamo tezine roditelja kako bi se generirale nove težine potomka
#računamo srednju vrijednsot težina roditelja po stupcima
#stvaramo novu matricu težina gdje svaki element predstavlja srednju vrijednost težina roditelja za odgovarajući stupac
def krizajTezine(roditeljiTezine):
    return np.mean(roditeljiTezine, axis=0) #rezultat su nove težine potomka, isto je, ja sam stavio oba jer nisam znao koje je bolje

#krizamo pomake roditelja kako bi se generirali novi pomaci potomka
def krizajPomake(roditeljiPomaci):
    noviPomaci = [] #iteriramo kroz pomake roditelja po elementima(pozicijama pomaka)
    for tezinePomaka in zip(*roditeljiPomaci): #transponiramo matricu roditeljskih pomaka kako bismo mogli iterirati po stupcima
        srednjiPomaci = np.mean(tezinePomaka, axis=0) #nad svim stupcima računamo srednju vrijednost pomaka roditelja za određeni stupac
        noviPomaci.append(srednjiPomaci)
    return noviPomaci


#vršimo križanje jedinki iz populacije kako bismo generirali nove potomke
def krizanje(populacija):
    fitnessVrij = izracunajFitness(populacija) #izračunavamo fitness jedinki i vjerojatnosti selekcije za svaku jedinku na temelju fitness vrijednosti
    vjerojatnosti = izracunajVjerojatnosti(fitnessVrij)

    roditelji = birajRoditelje(populacija, vjerojatnosti) #odabiremo roditelje koristeći vjerojatnosti selekcije
    roditeljiTezine, roditeljiPomaci = zip(*roditelji) #težine i pomake roditelja izdvajamo iz parova roditelja

    noveTezine = krizajTezine(roditeljiTezine) #krizamo tezine i pomake roditelja kako bismo izgenerirali nove tezine i pomake
    noviPomaci = krizajPomake(roditeljiPomaci)

    return noveTezine, noviPomaci

#primjenjuje mutaciju na svaku jedinku u populaciji koristeći mutiraj tezine
def mutiraj(m, p, k):
    return [mutirajTezine(tezine, p, k) for tezine in m] #vraća mutiranu populaciju


#ako su vektori onda se mutacija primjenjuje na svaki element vektora koristeći mutiraj sloj
def mutirajTezine(tezine, p, k):
    if isinstance(tezine, list): #provjerava jesu li težine 1D ili višeD(vektor ili matrica)
        return [mutirajSloj(sloj, p, k) for sloj in tezine]
    return np.asarray([mutirajSloj(sloj, p, k) for sloj in tezine])


def mutirajSloj(sloj, p, k):
    if isinstance(sloj, list):      #također provjerava jesu li vrijednosti sloja vektori ili matrice
        return [mutirajVrijednost(vrij, p, k) for vrij in sloj] #ako su matrice primjenjuje se na svaki element matrice koristeći mutiraj vrijednost
    return np.asarray([mutirajVrijednost(vrij, p, k) for vrij in sloj])


def mutirajVrijednost(vrij, p, k):
    if random.random() < p: #provjerava hoće li se mutacija primjeniti na vrijednost, ako je slučajni broj manji od vjv mutacije mutacija se primjenjuje
        sum = np.random.normal(loc=0, scale=k, size=1)[0]
        return vrij + sum #mutacija se vrši dodavanjem slučajnog broja iz normalne distribucije(šum)
    return vrij



#služi za zadržavanje najboljih jedinki u populaciji
def primjeniElitizam(populacija, elitizam):
    populacija = np.asarray(populacija)   #pretvaramo populaciju u numpy niz    
    sortiranaPopulacija = populacija[np.argsort(populacija[:, 0])] #sortiramo populaciju na temelju fitnessa(prvom stupcu u populaciji), podrazumijeva se da je elitizam 1
    elitni = sortiranaPopulacija[:elitizam] #oznacavamo prvih elitizam jedinki iz sortirane populacije kao elitne
    return elitni.tolist() #vraćamo listu elitnih jedinki

#u praznu listu populacija sve do veličine populacije
#izgrađujemo neuronsku mrežu i uzimamo samo matricu težina i vektor pomaka
#svaka jedinka predstavlja jednu neuronsku mrežu s pripadajućim težinama i pomacima
def inicijalizirajPopulaciju(popsize, podaci, cilj, dimenzije):
    populacija = [
        izgradiMrezu(podaci, cilj, dimenzije)[:3]
        for _ in range(popsize)
    ]
    return populacija #dobiveni rezultat dodajemo kao jedinku u populaciju koju vraćamo

#evaluiramo svaku jedinku u populaciji izvršavanjem unaprijednog prolaza kroz mrežu
#u praznu listu evaluirana populacija dodajemo rezultat prolaza tj izlaznu vrijednost mreže
def evaluirajPopulaciju(populacija, podaci, cilj):
    evaluiranaPopulacija = [
        unaprijedniProlaz(podaci, cilj, kromosom[0], kromosom[1])
        for kromosom in populacija #težine i pomaci su dio kromosoma
    ]
    return evaluiranaPopulacija


def trainError(iteracija, populacija):
    populacija = np.asarray(populacija) #konvertiramo listu populacija u numpy niz
    minInd = np.argmin(populacija[:, 0]) #pronalazimo indeks jedinke u populaciji koja ima najmanju grešku
    minTrainError = populacija[minInd, 0]
    print(f"[Train error @{iteracija}]: {np.round(minTrainError, 5)}") #dobivenu vrijednost najmanje greške pohranjujemo u varijablu mintrainerror



def main():
    train = sys.argv[2]
    test = sys.argv[4]
    nn = sys.argv[6]
    popsize = int(sys.argv[8])
    elitism = int(sys.argv[10])
    p = float(sys.argv[12])
    K = float(sys.argv[14])
    iter = int(sys.argv[16])

    zaglavlje_train = np.genfromtxt(train, delimiter=',', dtype=str, max_rows=1) #prvi redak
    podaci = np.genfromtxt(train, delimiter=',') #svi podaci osim prvog retka
    podaci_train = podaci[1:, :-1] #bez zadnjeg stupca i bez prvog retka
    cilj_train = podaci[1:, -1] #zadnji stupac bez prvog retka je ciljna varijabla

    zaglavlje_test = np.genfromtxt(test, delimiter=',', dtype=str, max_rows=1)
    podaci = np.genfromtxt(test, delimiter=',') 
    podaci_test = podaci[1:, :-1]
    cilj_test = podaci[1:, -1]

    dimenzije_rjecnik = {   #ima puno mogućih arhitektura mreže pa je sve u rječniku
        '5s': [len(zaglavlje_train) - 1, 5, 1],
        '20s': [len(zaglavlje_train) - 1, 20, 1],
        '5s5s': [len(zaglavlje_train) - 1, 5, 5, 1]
    }

    dimenzije = dimenzije_rjecnik.get(nn) #dohvaćamo vrijednost arhitekture mreže

    warnings.filterwarnings("ignore", category=np.VisibleDeprecationWarning) #radi i s tim warningom
    warnings.filterwarnings("ignore", category=RuntimeWarning)


    print('Početak testa i inicijalizacije populacije:')
    startTime = time.time()

    populacija = np.asarray(inicijalizirajPopulaciju(popsize, podaci_train, cilj_train, dimenzije), dtype=object)
    #inicijaliziramo populaciju koja je konvertirana u numpy niz


    i=1
    while i <= iter: #koliko iteracija imamo toliko puta stvaramo novu generaciju
        iducaGeneracija = napraviIducuGeneraciju(populacija, elitism, p, K)

        if i % 2000 == 0: #svakih 2000 iteracija ispisujemo najmanju grešku na skupu za treniranje
            trainError(i, populacija)

        populacija = np.asarray(evaluirajPopulaciju(iducaGeneracija, podaci_train, cilj_train), dtype=object) #evaluiramo populaciju

        i += 1

    #stvaramo numpy niz greske koji sadrzi greske na testnom skupu za svaku jedinku u populaciji tako što prolazi kroz populaciju i izvršava unaprijedni prolaz za svaku jedinku na testnom skupu
    greske = np.asarray([unaprijedniProlaz(podaci_test, cilj_test, nn[1], nn[2])[0] for nn in populacija])
    minGreska = np.min(greske) #trazimo minimalnu gresku na testnom skupu
    print("[Test error]:", np.round(minGreska, 5))

    print('Kraj testa')
    endTime = time.time()
    ukupnoVrijeme = endTime - startTime
    print('Ukupno vrijeme po testu:', ukupnoVrijeme)


if __name__ == '__main__':
    main()
