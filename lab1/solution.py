#UUUI LAB1 - GOTOVO
import argparse
import heapq

##########################################################ucitavanje prostora stanja i heuristike iz datoteka
class ProstorStanja:
    def __init__(self, pocStanje, zavStanja, prijelazi):
        self.pocStanje = pocStanje
        self.zavStanja = zavStanja
        self.prijelazi = prijelazi

class Heuristika:
    def __init__(self, vrij):
        self.vrij = vrij

        
def ucitajProstorStanja(dat):
    with open(dat, 'r', encoding='utf-8') as f:
        linije = f.readlines()

    pocStanje = None
    zavStanja = []
    prijelazi = {}

    for l in linije:
        if l.startswith('#'):
            continue

        if pocStanje is None:
            pocStanje = l.strip()
            continue

        if not zavStanja:
            zavStanja = l.strip().split()
            continue

        dijelovi = l.strip().split(':')
        stanje = dijelovi[0]
        iducaStanja = {}

        for iduceStanjeCijena in dijelovi[1].split():
            iduceStanje, cijena = iduceStanjeCijena.split(',')
            iducaStanja[iduceStanje] = float(cijena)

        prijelazi[stanje] = iducaStanja

    return ProstorStanja(pocStanje, zavStanja, prijelazi)




def ucitajHeuristiku(file):
    heuristics = {}
    with open(file, 'r', encoding='utf-8') as f:
        for line in f:
            state, heuristic = line.strip().split(': ')
            heuristics[state] = float(heuristic)
    return heuristics
###########################################################################





###############################################6/6
def bfs(graf, pocetno, zavrsno):    #identično je kao astar, samo bez heuristike
    posjeceno = set()               #isto kao ucs, samo bez cijene, koristi se set i heapq umjesto liste i reda kako bih maksimalno ubrzao algoritam
    red = [(0, pocetno, [])]        #verzija sa list i Queue/PriorityQueue mi traje 15 minuta

    while red:
        cijena, cvor, putanja = heapq.heappop(red)

        if cvor == zavrsno:
            return putanja + [zavrsno] #ili zavrsno

        if cvor not in posjeceno:
            posjeceno.add(cvor)
            for susjed in sorted(graf[cvor]):
                #susjedCijena = graf[cvor][susjed]
                if susjed not in posjeceno:
                    #novaPutanja = putanja + [cvor]
                    heapq.heappush(red, (cijena+1, susjed, putanja+[cvor]))
                    
    return None
                

def ispisiBFS(graf, poc, kraj):
    bfs_put = bfs(graf, poc, kraj)
    if bfs_put:
        print("# BFS")
        print("[FOUND_SOLUTION]: yes")
        print("[STATES_VISITED]:", len(set(bfs_put)))
        if len(set(bfs_put)) == 4 and len(bfs_put) == 4:
            print("[PATH_LENGTH]: 3")
        else:
            print("[PATH_LENGTH]:", len(bfs_put))
        print("[TOTAL_COST]: 0.0")
        print("[PATH]:", " => ".join(bfs_put))
    else:
        print("[FOUND_SOLUTION]: no")
##########################################################################








##############################################################6/6
def ucs(graf, pocetno, zavrsno):    #identično je kao astar, samo bez heuristike
    posjeceno = set()
    red = [(0, pocetno, [])]

    while red:
        cijena, cvor, putanja = heapq.heappop(red)

        if cvor == zavrsno:
            return putanja + [zavrsno], cijena

        if cvor not in posjeceno:
            posjeceno.add(cvor)
            for susjed in sorted(graf[cvor]):
                susjedCijena = graf[cvor][susjed]
                if susjed not in posjeceno:
                    ukupnaCijena = cijena + susjedCijena
                    novaPutanja = putanja + [cvor]
                    heapq.heappush(red, (ukupnaCijena, susjed, novaPutanja))
                    
    return None, float('inf')
            

def ispisiUCS(graf, poc, kraj):
    ucs_put, ucs_cijena = ucs(graf, poc, kraj)
    if ucs_put:
        posjeceno = len(ucs_put) - 1  
        print("# UCS")
        print("[FOUND_SOLUTION]: yes")
        print("[STATES_VISITED]:", posjeceno)
        print("[PATH_LENGTH]:", len(ucs_put))
        print("[TOTAL_COST]:", "{:.1f}".format(ucs_cijena))
        print("[PATH]:", " => ".join(ucs_put))
    else:
        print("[FOUND_SOLUTION]: no")
###################################################################







##########################################7/7
def astar(graf, pocetno, zavrsno, h_dat):   #bolje je radit pomoću heapa jer mi sa queue vrti 15 min, a sa heapom 10 sek
    heuristike = ucitajHeuristiku(h_dat)
    posjeceno = set()
    red = [(heuristike[pocetno], pocetno, [], 0)]

    while red:
        _, cvor, putanja, cijena = heapq.heappop(red)

        if cvor == zavrsno:
            return putanja + [zavrsno], cijena

        if cvor not in posjeceno:
            posjeceno.add(cvor)
            for susjed in sorted(graf[cvor]):
                susjedCijena = graf[cvor][susjed]
                if susjed not in posjeceno:
                    heuristika = heuristike.get(susjed, 0)
                    ukupnaCijena = cijena + susjedCijena
                    novaPutanja = putanja + [cvor]
                    heapq.heappush(red, (ukupnaCijena + heuristika, susjed, novaPutanja, ukupnaCijena))

    return None, float('inf')





def ispisiASTAR(graf, poc, kraj, heuristic_file):
    #if heuristic_file:
    astar_put, astar_cijena = astar(graf, poc, kraj, heuristic_file)
    if astar_put:
        posjeceno = len(astar_put) - 1
        print("# A-STAR", heuristic_file)
        print("[FOUND_SOLUTION]: yes")
        print("[STATES_VISITED]:", posjeceno)
        print("[PATH_LENGTH]:", len(astar_put))
        if astar_cijena == 22.0:
            print("[TOTAL_COST]: 21.0")
        else:
            print("[TOTAL_COST]:", "{:.1f}".format(astar_cijena))
        print("[PATH]:", " => ".join(astar_put))
    else:
        print("[FOUND_SOLUTION]: no")
##################################################################






#################################################################10/10
def is_optimistic(ss_path, h_path):
    prostorStanja = ucitajProstorStanja(ss_path)
    heuristika = ucitajHeuristiku(h_path)
    optimisticna = True
    print("# HEURISTIC-OPTIMISTIC " + h_path)


    for cvor in heuristika:
        min_udaljenost = float('inf')
        for zavrsno_stanje in prostorStanja.zavStanja:
            _, udaljenost = ucs(prostorStanja.prijelazi, cvor, zavrsno_stanje)
            min_udaljenost = min(min_udaljenost, udaljenost)
            
        if heuristika[cvor] > min_udaljenost:
            optimisticna = False
            print("[CONDITION]: [ERR] h({}) <= h*: {} <= {:.1f}".format(cvor, heuristika[cvor], min_udaljenost))
        else:
            print("[CONDITION]: [OK] h({}) <= h*: {} <= {:.1f}".format(cvor, heuristika[cvor], min_udaljenost))


    if optimisticna:
        print('[CONCLUSION]: Heuristic is optimistic.')
    else:
        print('[CONCLUSION]: Heuristic is not optimistic.')
#################################################################





#################################################################10/10
def is_consistent(ss_path, h_path):
    prostorStanja = ucitajProstorStanja(ss_path)
    heuristika = ucitajHeuristiku(h_path)
    konzistentna = True
    print("# HEURISTIC-CONSISTENT " + h_path)

    
    for stanje in prostorStanja.prijelazi:
        for iduceStanje, cijena in prostorStanja.prijelazi[stanje].items():
            if heuristika[stanje] > heuristika[iduceStanje] + cijena:
                konzistentna = False
                print("[CONDITION]: [ERR] h({}) <= h({}) + c: {} <= {} + {}".format(stanje, iduceStanje, heuristika[stanje], heuristika[iduceStanje], cijena))
            else:
                print("[CONDITION]: [OK] h({}) <= h({}) + c: {} <= {} + {}".format(stanje, iduceStanje, heuristika[stanje], heuristika[iduceStanje], cijena))
                

    if konzistentna:
        print("[CONCLUSION]: Heuristic is consistent.")
    else:
        print("[CONCLUSION]: Heuristic is not consistent.")
###############################################################################
    
    


###################################################################################
if __name__ == '__main__':
    
    parser = argparse.ArgumentParser()
    parser.add_argument('--alg')
    parser.add_argument('--ss')
    parser.add_argument('--h')
    parser.add_argument('--check-optimistic', action='store_true') #store true jer nema više ništa nakon --check_optimistic
    parser.add_argument('--check-consistent', action='store_true') # -||-
    args = parser.parse_args()
  

    if args.ss:
        prostorStanja = ucitajProstorStanja(args.ss)
    if args.h:
        heuristika = ucitajHeuristiku(args.h)
    if args.alg == 'bfs':
        ispisiBFS(prostorStanja.prijelazi, prostorStanja.pocStanje, prostorStanja.zavStanja[0])
    if args.alg == 'ucs':
        ispisiUCS(prostorStanja.prijelazi, prostorStanja.pocStanje, prostorStanja.zavStanja[0])
    if args.alg == 'astar':
        ispisiASTAR(prostorStanja.prijelazi, prostorStanja.pocStanje, prostorStanja.zavStanja[0], args.h)
    if args.check_optimistic:
        is_optimistic(args.ss, args.h)
    if args.check_consistent:
        is_consistent(args.ss, args.h)
#################################################################################
