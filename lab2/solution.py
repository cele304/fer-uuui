#UI LAB2

def provjeri(klauzule):     #koristi u njoj definirane fje kako bi uklonila sav višak i vratila skup klauzula bez tih elemenata
    zaUklanjanje = set()
    zaUklanjanje.update(ukloniDupleKlauzule(klauzule))
    zaUklanjanje.update(pronadiTautologije(klauzule))
    zaUklanjanje.update(pronadiPodskupove(klauzule))
    return ukloni(zaUklanjanje, klauzule)

def ukloniDupleKlauzule(klauzule):      #ukloni duplikate klauzula iz skupa klauzula
    return list(set(map(tuple, klauzule)))


def pronadiTautologije(klauzule):   #pronadi sve klauzule koje u sebi imaju a i ~a
    duple_klauzule = set()

    for i, klauzula in enumerate(klauzule):
        for literal in klauzula:
            negacija = negate(literal)
            if negacija in klauzula:
                duple_klauzule.add(i)
                break
    
    return duple_klauzule

def pronadiPodskupove(klauzule):    #pronadi klauzule koje su podskupovi drugih klauzula
    podskupovi = set()

    for i, klauzula1 in enumerate(klauzule):
        for j, klauzula2 in enumerate(klauzule):
            if i != j:
                if set(klauzula1).issubset(klauzula2):
                    podskupovi.add(j)
    
    return podskupovi

def ukloni(zaUklanjanje, klauzule): #vraća listu klauzula koje su uklonjene klauzule čiji su indeksi navedeni u zaUklanjanje
    return [klauzule[i] for i in range(len(klauzule)) if i not in zaUklanjanje]


def oznaci(premise, sos):   #prođi kroz sve kombinacije premisa-sos i sos-sos
    oznaceno = kombinacije1(premise, sos)
    oznaceno += kombinacije2(sos)
    return oznaceno

def kombinacije1(premise, sos): #oznaci sve kombinacije premisa-sos
    return [(premisa, s) for premisa in premise for s in sos]

def kombinacije2(sos):      #oznaci sve kombinacije sos-sos
    return [(sos[i], sos[j]) for i in range(len(sos) - 1) for j in range(i + 1, len(sos))]


def razrjesi(prvi, drugi):
    if len(prvi) == 1 and len(drugi) == 1 and prvi[0] == negate(drugi[0]): return ["NIL"] #ako imaš za razriješiti samo a i ~a
    if not pronadiLiteral(prvi, drugi): return []
    return izvediLiterale(prvi, drugi)


def pronadiLiteral(prvi, drugi):    #pronadi literale u klauzulama koji se mogu razriješiti
    pronadeno = False
    pronadeno = any(negate(literal) in drugi for literal in prvi)
    return pronadeno


def izvediLiterale(prvi, drugi): #ukloni literale iz klauzula za razrješavanje i izvedi novu klauzulu
    izvedeno = []
    izvedeno = [literal for literal in prvi if negate(literal) not in drugi]
    izvedeno += [literal for literal in drugi if negate(literal) not in prvi]
    return izvedeno

def primjeniRezolucijuOpovrgavanjem(premise, cilj):
    sos = [[negate(literal)] for literal in cilj]       #dodaj klauzule negiranog cilja u skup potpore
    br = 1                                              #broj iteracije
    posjeceno = set()                                   #skup klauzula koje su provjerene u prethodnim iteracijama
    while True:
        sos = provjeri(sos)     #provjerava da li se u sosu nalaze dvije klauzule koje se mogu rezolvirati, te ako da, rezolvira ih i dodaje dobivenu klauzulu u sos
        if not sos:             #ako je sos prazan -  nije moguće opovrgnuti cilj
            printNeuspjeh(cilj)
            return   
        nove = []               #nove klauzule koje dodajemo u sos
        for par in oznaci(premise, sos):        #provjerava da li se kombinacije klauzula iz premisa i sosa mogu razrjesiti, te ako mogu, vraća par klauzula koji se mogu razrjesiti
            rezolvente = razrjesi(par[0], par[1]) #provjerava da li se dvije klauzule mogu rezolvirati, te ako mogu, vraća rezolvente, odnosno nove klauzule koje su dobivene rezolucijom
            if "NIL" in rezolvente:     #ako se u listi rezolvente nalazi string "NIL", tada je cilj opovrgnut i funkcija daje poruku o uspješno izvršenoj rezoluciju
                print(f"Prolaz {br}:")
                print(f"NIL ({' v '.join(par[0])}, {' v '.join(par[1])})")
                printUspjeh(cilj)               #uspjeli smo izvršiti rezoluciju opovrgavanjem
                return
            if rezolvente and tuple(rezolvente) not in posjeceno: #ako rezolvente lista nije prazna i ako nisu već provjerene, tada se dodaju u listu nove
                posjeceno.add(tuple(rezolvente))                #dodaje se nova klauzula u set posjeceno kako bi se spriječilo ponovno provjeravanje iste klauzule
                nove.append(rezolvente)                         #dodaj novu klauzulu u listu novih klauzula
                print(f"Prolaz {br}:")
                for klauzula in nove:
                    print(f"{' v '.join(klauzula)} ({' v '.join(par[0])}, {' v '.join(par[1])})")
        if not nove:                                #ako je lista novih klauzula prazna - rezolucija se ne može izvršiti
            printNeuspjeh(cilj)                     #nismo uspjeli izvršiti rezoluciju opovrgavanjem
            return
        nove = provjeri(nove)                       #provjerava da li se u listi nove nalaze dvije klauzule koje se mogu rezolvirati, te ako da, rezolvira ih i dodaje dobivenu klauzulu u nove
        if all(tuple(klauzula) in set(map(tuple, sos)) for klauzula in nove): #provjerava da li su sve klauzule iz nove već prisutne u sosu. Ako jesu, tada se zaključuje da nije moguće opovrgnuti cilj i funkcija ispisuje poruku o neuspjehu i vraća se
            printNeuspjeh(cilj)                 #nismo uspjeli izvršiti rezoluciju opovrgavanjem
            return
        sos += nove                             #dodaj nove klauzule u skup potpore
        br += 1


def printUspjeh(cilj):          #uspjeli smo izvršiti rezoluciju opovrgavanjem
    print('====================')
    print(f"[CONCLUSION]: {' v '.join(cilj)} is true")
    
def printNeuspjeh(cilj):        #nismo uspjeli izvršiti rezoluciju opovrgavanjem
    print('====================')
    print(f"[CONCLUSION]: {' v '.join(cilj)} is unknown")
    

def negate(literal):    #negiraj literal
    return literal[1:] if literal[0] == '~' else '~' + literal

def ucitajKlauzule(dat):
    premise = []
    print('====================')
    print('Pocetne premise:\n', end='')
    br = 1

    with open(dat, encoding="utf-8") as f:
        for linija in f:
            if linija.startswith("#"):      #preskoči komentare
                continue
            premise += [linija.strip().lower().split(" v ")] #dodaj sve linije u skup premisa
            print(f"{br}. {linija.lower()}", end='')
            br += 1

    cilj = premise.pop()    #cilj je zadnja klauzula iz datoteke
    negiraniCilj = " v ".join(negate(literal) for literal in cilj) #negiraj cilj i izvedi eventualne nove klauzule
    negiraniCiljBr = ""

    for i, klauzula in enumerate(negiraniCilj.split(" v "), start=br): #ispiši sve klauzule negiranog cilja
        negiraniCiljBr += f"{i-1}. {klauzula}\n"
    print('====================')
    print("Negirani cilj:\n" + negiraniCiljBr)
    print('====================')
    premise.insert(0, negiraniCilj.split(" v "))    #dodaj negirani cilj na početak niza premises
    primjeniRezolucijuOpovrgavanjem(premise, cilj)  #izvrši rezoluciju opovrgavanjem nad učitanim klauzulama


def ucitajKlauzuleZaKuhanje(dat, dat2):
    premise = []
    print('====================')
    print('Constructed with knowledge:')
    br = 1

    with open(dat, encoding="utf-8") as f:  #učitavamo klauzule iz datoteke sa klauzulama
        for linija in f:
            if linija.startswith("#"):
                continue
            premise += [linija.strip().lower().split(" v ")]

            print(f"{br}. {linija.lower()}", end='')

            br += 1

    with open(dat2, encoding="utf-8") as f2:    #učitavamo naredbe iz linije s naredbama
        for linija in f2:
            linija = linija.strip().lower()
            
            if linija.strip() == "":
                continue
            
            print(f"User's command: {linija}")

            if 'v' in linija:       #klauzula je cijela linija osim zadnjeg znaka
                klauzula = linija[:-1].strip().split(" v ")
            else:
                klauzula = linija[:-1].strip().split()
            
            premise.append(klauzula)            #dodaj tu klauzulu u skup klauzula

            cilj = premise.pop()                #cilj je sad ta zadnja klauzula koju smo dodali
            negiraniCilj = " v ".join(negate(literal) for literal in cilj) #negiraj cilj
            negiraniCiljBr = ""

            znak = linija[-1]   #znak je zadnji dio linije

            if znak == '+':
                dodajKlauzulu(premise, klauzula)
            elif znak == '-':
                obrisiKlauzulu(premise, klauzula)
            elif znak == '?':
                provjeriKlauzulu(premise, klauzula)
            else:
                print("Invalid command")
                continue

    return premise, negiraniCiljBr




def provjeriKlauzulu(premise, klauzula):    #primjeni rezoluciju opovrgavanjem nad učitanim premisama i novom klauzulom
    primjeniRezolucijuOpovrgavanjem(premise, klauzula)


def dodajKlauzulu(premise, klauzula):
    premise.append(klauzula)            #dodaj novu klauzulu iz skupa naredbi u skup klauzula
    if klauzula is not None:
        print(f"Added {' v '.join(klauzula)}")
    else:
        print('Greška')


def obrisiKlauzulu(premise, klauzula):  #izbrisi odredenu klauzulu iz skupa klauzula
    premise.remove(klauzula)
    if klauzula is not None:
        print(f"Removed {' v '.join(klauzula)}")
    else:
        print(f"Klauzula {' v '.join(klauzula)} not found in the list")


import sys

def main():
    if sys.argv[1] == 'resolution': #ako je naredba resolution primjeni rezoluciju 
        ucitajKlauzule(sys.argv[2])

    if sys.argv[1] == 'cooking': #inače primjeni kuhanje
        premise, negiraniCilj = ucitajKlauzuleZaKuhanje(sys.argv[2], sys.argv[3])


if __name__ == "__main__":
    main()
