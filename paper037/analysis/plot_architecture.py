"""Generate the conceptual figure; measured data and the original photo are unchanged."""
from pathlib import Path
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

OUT = Path(__file__).resolve().parents[1] / 'manuscript' / 'figures'
plt.rcParams.update({'font.family': 'DejaVu Sans', 'font.size': 8.4, 'pdf.fonttype': 42})
fig, ax = plt.subplots(figsize=(6.89, 4.7))
fig.subplots_adjust(left=.012, right=.988, bottom=.02, top=.98)
ax.set(xlim=(0, 10), ylim=(0, 7)); ax.axis('off')
blue, teal, dark = '#dceaf5', '#dff0e9', '#173047'
boxes=[]
def box(x,y,w,h,t,fc=blue,fs=8.4):
    patch=FancyBboxPatch((x,y),w,h,boxstyle='round,pad=0.04,rounding_size=0.08',fc=fc,ec='#547084',lw=.9)
    ax.add_patch(patch)
    txt=ax.text(x+w/2,y+h/2,t,ha='center',va='center',fontsize=fs,color=dark,linespacing=1.4)
    boxes.append((patch,txt))
def arrow(a,b):
    ax.add_patch(FancyArrowPatch(a,b,arrowstyle='-|>',mutation_scale=11,lw=1.1,color='#547084',shrinkA=2,shrinkB=2))
ax.text(.12,6.72,'(a) Release semantics',weight='bold',fontsize=10,color=dark)
box(.16,5.32,2.13,1.12,'Feature contract\norder, units, domain',fs=8.2)
box(2.68,5.32,2.13,1.12,'Preprocessing\ntransform, mean, scale',fs=8.2)
box(5.20,5.32,2.13,1.12,'Model and\nquantization\nweights, scales',fs=8.2)
box(7.72,5.32,2.13,1.12,'Decision policy\nthreshold, comparison',fs=8.2)
for x in [2.29,4.81,7.33]: arrow((x,5.88),(x+.39,5.88))
ax.add_patch(FancyBboxPatch((.055,5.15),9.90,1.43,boxstyle='round,pad=0.01,rounding_size=.06',fc='none',ec='#27816b',lw=1.3))
ax.text(5,4.72,'Signed package: contract digest, runtime ABI, version, and complete parameters',ha='center',va='center',fontsize=8.2,color='#236b59')
ax.text(.12,4.16,'(b) Installation and selection',weight='bold',fontsize=10,color=dark)
box(.18,2.38,2.28,1.38,'Candidate checks\nsignature and version\ncontract and ABI',teal)
box(3.13,2.38,2.70,1.38,'Inactive slot\nerase, write, read back\nverify, slot commit',teal)
box(6.54,2.38,3.28,1.38,'Selector journal\nsequence, version, slot, digest\nbody, then selector commit',teal,fs=8.15)
arrow((2.49,3.07),(3.07,3.07)); arrow((5.87,3.07),(6.47,3.07))
box(.18,.45,2.28,1.13,'Compatible export\ntransform parameters\nverify equivalence',fc='#f0f2f4',fs=8.1)
box(3.13,.45,2.70,1.13,'Old release remains\nauthoritative until\nselector commit',fc='#f0f2f4')
box(6.54,.45,3.28,1.13,'Boot selects complete release\nmatching the committed\nselector entry',fc='#f0f2f4')
arrow((4.48,2.32),(4.48,1.64)); arrow((8.18,2.32),(8.18,1.64))
# Enforce label containment at the actual print size.
fig.canvas.draw();renderer=fig.canvas.get_renderer()
for patch,txt in boxes:
    b=patch.get_window_extent(renderer);t=txt.get_window_extent(renderer)
    assert b.x0 <= t.x0 and b.x1 >= t.x1 and b.y0 <= t.y0 and b.y1 >= t.y1, txt.get_text()
for ext in ['pdf','png']:
    fig.savefig(OUT/('pipeline_architecture.'+ext),dpi=240,bbox_inches='tight')
plt.close(fig)
print('Wrote pipeline_architecture (PDF + PNG); every label fits its box.')
