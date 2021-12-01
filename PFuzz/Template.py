from .Utils import PFuzzSplitStrCommon

class PFuzzTemplate:
    def __init__(self,pieces:dict,gaps:dict):
        self.pieces = pieces
        self.gaps = gaps
        if len(pieces) != len(gaps) + 1:
            raise

    def generate(self,values:list):
        tmp = []
        pos = []
        nidx = len(self.gaps)
        for p in self.pieces:
            tmp.append(p)
            if nidx:
                tmp.append(self.gaps[len(self.gaps)-nidx])
                pos.append(len(tmp)-1)
                nidx -= 1
        for val in values:
            for i in pos:
                saved = tmp[i]
                tmp[i] = val
                yield ''.join(tmp)
                tmp[i] = saved


def PFuzzBuildDifferTemplate(X,Y)->PFuzzTemplate:
    cs = PFuzzSplitStrCommon(X,Y)
    if not len(cs):
        return PFuzzTemplate([''],[])
    needCheck = False
    gaps = []
    tmp = []
    isGap = False
    back = X
    front = ''
    tp = len(cs)
    for piece in cs:
        idx = back.index(piece)
        gaps.append(idx+len(front))
        tmp.append(piece)
        front += back[:idx+len(piece)]
        back = back[idx+len(piece):]

        tp -= 1
        
        if isGap:
            gaps = gaps[:-2] + [X[gaps[-2]+len(tmp[-2]):gaps[-1]],gaps[-1]]
            if not tp and isinstance(gaps[-1],int):
                gaps = gaps[:-1]
        else:
            isGap = True
            
        if len(cs) == 1 and back == '':
            gaps = []

        if not tp and back != '':
            if len(cs) == 1:
                gaps = gaps[1:]
            cs = cs + ['']
            gaps = gaps + [back]
        else:
            needCheck = True    
    
    if X.index(cs[0]) != 0:
        gaps = [X[:X.index(cs[0])]] + gaps
        cs = [''] + cs
    
    if needCheck and len(X) < len(Y):
        cs = cs + ['']
        gaps = gaps + ['']
    return PFuzzTemplate(cs,gaps)

            
            
                




    