"""Rebuild four paper figures from the supplied, source-linked curated JSON.
Usage: python analysis/plot_hardware.py [--output manuscript/figures]
Requires Python, numpy and matplotlib; no device or source dataset is needed.
"""
from pathlib import Path
import argparse, json
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import Patch
from matplotlib.colors import ListedColormap
P=Path(__file__).resolve().parent
D=json.loads((P/'hardware_evidence.json').read_text())
arg=argparse.ArgumentParser();arg.add_argument('--output',type=Path,default=P.parent/'manuscript/figures');A=arg.parse_args();A.output.mkdir(parents=True,exist_ok=True)
plt.rcParams.update({'font.family':'DejaVu Sans','font.size':9,'axes.titlesize':10,'axes.labelsize':9,'legend.fontsize':8,'xtick.labelsize':8,'ytick.labelsize':8,'axes.spines.top':False,'axes.spines.right':False,'pdf.fonttype':42,'ps.fonttype':42,'figure.facecolor':'white','axes.axisbelow':True})
BLUE='#2878A5';ORANGE='#CE6B26';GREEN='#218774';GRAY='#556271'; LIGHT='#EAF0F3'
FAMS=['lr','dt','mlp_float','mlp_int8'];LAB=['LR','DT','MLP-F32','MLP-I8'];POL=['bundle','whole'];COL=[BLUE,ORANGE]
def save(fig,name):
 fig.savefig(A.output/(name+'.pdf'),bbox_inches='tight')
 fig.savefig(A.output/(name+'.png'),bbox_inches='tight',dpi=240)
 plt.close(fig)
def finish(ax,xlabels=LAB):
 ax.set_xticks(range(len(xlabels)),xlabels);ax.grid(axis='y',alpha=.22)
def panel(ax,text):ax.set_title(text,loc='left',fontweight='bold',pad=10)
def values(f,p,key,den=1):return np.array([r[key]/den for r in D['cost030']['primary_rows'] if r['family']==f and r['policy']==p])
# 1. Distinct denominators prevent protocol roundtrips being presented as MCU time.
fig,axs=plt.subplots(2,2,figsize=(6.89,5.5)); fig.subplots_adjust(hspace=.48,wspace=.42,top=.88,bottom=.08)
for ai,(ax,key,den,title,unit) in enumerate(zip(axs.flat,['payload_or_image_bytes','tx_wire_bytes','device_active_us','host_elapsed_ns'],[1,1,1000,1e9],['(a) Signed artifact','(b) Protocol transmission','(c) MCU intervals','(d) USB end-to-end update'],['Bytes','Bytes','Time (ms)','Time (s)'])):
 for j,(p,c) in enumerate(zip(POL,COL)):
  for i,f in enumerate(FAMS):
   y=values(f,p,key,den)
   if ai==0 and p=='whole':y=y+340 # 84-byte metadata and 256-byte RSA signature
   xpos=i+(-.18 if j==0 else .18)
   if ai<2:
    ax.bar(xpos,np.median(y),width=.30,color=c,zorder=3)
   else:
    ax.scatter(xpos+np.linspace(-.065,.065,len(y)),y,s=15,c=c,alpha=.7,edgecolors='white',linewidths=.3,zorder=3)
    ax.plot([xpos-.10,xpos+.10],[np.median(y)]*2,c=c,lw=2.2,zorder=4)
   label=(f'{np.median(y):,.0f}' if ai<2 else (f'{np.median(y):.1f}' if ai==2 else f'{np.median(y):.3f}'))
   # Keep small package labels to the left of the adjacent full-image bar.
   # On a log axis the full-image bar extends behind these labels otherwise.
   label_x=xpos+.12 if ai<2 and p=='bundle' else xpos
   label_ha='right' if ai<2 and p=='bundle' else 'center'
   ax.text(label_x,np.max(y)*1.22,label,ha=label_ha,va='bottom',fontsize=7.4,rotation=0,zorder=5)
 ax.set_yscale('log');ax.set_ylabel(unit);panel(ax,title);finish(ax)
 ax.set_ylim((100,2500000) if ai<2 else ((10,4000) if ai==2 else (.03,35)))
fig.legend([Patch(color=BLUE),Patch(color=ORANGE)],['Package','Full image'],loc='upper center',bbox_to_anchor=(.5,.99),ncol=2,frameon=False)
save(fig,'hardware_costs')
# 2. Show all 30 pairs separately; first fill is descriptive, reused is primary.
fig,axs=plt.subplots(1,3,figsize=(6.89,3.3),gridspec_kw={'width_ratios':[1,1,1.15]});fig.subplots_adjust(wspace=.70,top=.79,bottom=.17)
records=D['erase025']['records']
for j,(trans,title) in enumerate([('A_to_B_clean','(a) First fill'),('B_to_C_reused','(b) Reused slot')]):
 ax=axs[j]
 for i,f in enumerate(['lr','dt']):
  ys=[]
  for k,(pol,col) in enumerate([('full_slot',ORANGE),('necessary_sectors',BLUE)]):
   rows=sorted([r for r in records if r['configuration']==f+'_'+pol and r['transition']==trans],key=lambda r:r['block'])
   y=np.array([r['timing_us']['total']/1000 for r in rows]);ys.append(y);xp=i+(-.18 if k==0 else .18)
   ax.scatter(xp+np.linspace(-.04,.04,30),y,s=10,color=col,alpha=.65,zorder=3)
   ax.plot([xp-.13,xp+.13],[np.median(y)]*2,c=col,lw=2)
   ax.text(xp,np.max(y)+(.15 if j==0 else 1),f'{np.median(y):.2f}',ha='center',fontsize=8)
  for u,v in zip(*ys):ax.plot([i-.18,i+.18],[u,v],color='#AAB7C0',alpha=.28,lw=.5,zorder=1)
 ax.set_ylim((7,13) if j==0 else (18,52));finish(ax,['LR','DT']);ax.set_ylabel('Engine interval (ms)');panel(ax,title)
ax=axs[2]
for i,f in enumerate(['lr','dt']):
 d=D['erase025']['paired'][f+'/B_to_C_reused'];y=np.array(d['per_block_differences'])/1000
 ax.scatter(i+np.linspace(-.12,.12,30),y,color=GREEN,s=13,alpha=.55,zorder=3)
 med=d['difference']['median']/1000;ci=np.array(d['ci95'])/1000
 ax.errorbar(i,med,yerr=np.array([[med-ci[0]],[ci[1]-med]]),fmt='D',color='#183B4E',capsize=6,lw=2,zorder=4)
 ax.text(i,-25.5,f'{med:.2f}',ha='center',va='center',fontsize=8,fontweight='bold')
ax.axhline(0,c=GRAY,lw=.8,ls='--');ax.set_ylim(-28,3);ax.set_xlim(-.5,1.5);finish(ax,['LR','DT']);ax.set_ylabel('4 KiB minus 64 KiB (ms)');panel(ax,'(c) Paired difference')
fig.legend([Patch(color=ORANGE),Patch(color=BLUE)],['64 KiB erase request','4 KiB erase request'],loc='upper center',bbox_to_anchor=(.5,1.02),ncol=2,frameon=False)
save(fig,'erase_ablation')
# 3. Recovery matrix explicitly separates firmware campaigns and n per cell.
check=['after_erase','after_write','after_verify','after_slot_commit','after_journal_body','after_commit']
ylab=['After target erase','After payload write','After readback verification','After slot commit','After selector body','After selector commit']
fig,axs=plt.subplots(1,3,figsize=(6.89,3.8),sharey=True,gridspec_kw={'width_ratios':[1,1,1]});fig.subplots_adjust(wspace=.13,left=.245,bottom=.13,top=.80)
columns=[['LR\nclean','LR\nreused','DT\nclean','DT\nreused'],['LR\n64\nKiB','LR\n4\nKiB','DT\n64\nKiB','DT\n4\nKiB'],['LR','DT','MLP-\nF32','MLP-\nI8']]
allcounts=[]
for k,ax in enumerate(axs):
 mat=np.tile(np.array([0,0,0,0,0,1])[:,None],(1,4));ax.imshow(mat,cmap=ListedColormap(['#E5EFF6','#CAEBDD']),vmin=0,vmax=1,aspect='auto')
 for i,c in enumerate(check):
  for j in range(4):
   if k==0:
    fam='lr' if j<2 else 'dt';cond='clean' if j%2==0 else 'reused';cells=[x for x in D['software_faults']['stage020_cells'] if x['model']==fam and x['target_condition']==cond and x['checkpoint']==c]
   elif k==1:
    conf=('lr' if j<2 else 'dt')+'_'+('full_slot' if j%2==0 else 'necessary_sectors');cells=[x for x in D['software_faults']['stage025_cells'] if x['configuration']==conf and x['checkpoint']==c]
   else:cells=[x for x in D['software_faults']['stage030_cells'] if x['family']==FAMS[j] and x['checkpoint']==c]
   assert len(cells)==1;n=cells[0]['n'];allcounts.append(n)
   ax.text(j,i,f'{n}/{n}\n'+('new' if i==5 else 'old'),ha='center',va='center',fontsize=8,color='#204555')
 ax.set_xticks(range(4),columns[k],fontsize=7);ax.tick_params(axis='both',length=0);ax.set_yticks(range(6),ylab);ax.set_xticks(np.arange(-.5,4,1),minor=True);ax.set_yticks(np.arange(-.5,6,1),minor=True);ax.grid(which='minor',color='white',lw=2);ax.tick_params(which='minor',length=0)
 ax.set_title(['(a) H1: Baseline\n240 checkpoint tests','(b) H2: Erase ablation\n24 checkpoint tests','(c) H3: Four-model\n24 checkpoint tests'][k],fontsize=8,fontweight='bold',pad=10)
 for s in ax.spines.values():s.set_visible(False)
assert sum(allcounts)==288
save(fig,'software_recovery')
# 4. Raw 10-block energy points, not 128/4 pseudo-replicates; gross and net separate.
fig,axs=plt.subplots(1,2,figsize=(6.89,3.5));fig.subplots_adjust(wspace=.38,bottom=.13,top=.80)
for j,(ax,key,title) in enumerate(zip(axs,['gross_mJ_per_update','net_mJ_per_update'],['(a) Gross recorded energy','(b) Above idle baseline'])):
 for k,(p,c) in enumerate(zip(POL,COL)):
  for i,f in enumerate(FAMS):
   pts=sorted([x for x in D['energy031']['block_points'] if x['family']==f and x['policy']==p],key=lambda x:x['block']);y=np.array([x[key] for x in pts]);xx=i+(-.17 if k==0 else .17)+np.linspace(-.065,.065,10)
   if j==1:
    lo=np.array([x['net_sensitivity_mJ_per_update'][0] for x in pts]);hi=np.array([x['net_sensitivity_mJ_per_update'][1] for x in pts]);ax.vlines(xx,lo,hi,color=c,alpha=.28,lw=.6,zorder=2)
   ax.scatter(xx,y,s=17,color=c,alpha=.70,edgecolors='white',linewidths=.25,zorder=3)
   ax.plot([np.mean(xx)-.11,np.mean(xx)+.11],[np.median(y)]*2,color=c,lw=2.2,zorder=4)
   ax.text(np.mean(xx),np.max(y)*1.18,f'{np.median(y):.2f}' if k==0 else f'{np.median(y):.1f}',ha='center',va='bottom',fontsize=8)
 ax.set_yscale('log');ax.set_ylim((30,4200) if j==0 else (4,800));ax.set_ylabel('Energy per accepted update (mJ)');finish(ax);panel(ax,title)
fig.legend([Patch(color=BLUE),Patch(color=ORANGE)],['Package: 128 updates/block','Full image: 4 updates/block'],loc='upper center',bbox_to_anchor=(.5,1.01),ncol=2,frameon=False)
save(fig,'energy_blocks')
print('Wrote hardware_costs, erase_ablation, software_recovery, energy_blocks (PDF + PNG).')
