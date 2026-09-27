"""Rebuild all five science figures and numeric LaTeX tables from curated JSON.

Dependencies: Python 3.10+, numpy, matplotlib. No network, GPU, MCU or source CSV
is required. This is figure reproduction, not a rerun of full traffic inference.
"""
from pathlib import Path
import argparse, json
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.colors import LogNorm
from matplotlib.ticker import MaxNLocator

HERE=Path(__file__).resolve().parent
FAMILIES=['lr','dt','mlp_float','mlp_int8']
FAMILY_NAMES=['LR','DT','MLP-F32','MLP-I8']
COLORS=['#275D87','#C56A2D','#278275','#8D5999']
VARIANTS=[
 ('lr_stale_scaler','LR: stale scaler'),
 ('lr_stale_threshold','LR: stale threshold'),
 ('lr_stale_scaler_threshold','LR: stale scaler + threshold'),
 ('dt_stale_threshold','DT: stale threshold'),
 ('mlp_float_stale_scaler','MLP-F32: stale scaler'),
 ('mlp_float_stale_threshold','MLP-F32: stale threshold'),
 ('mlp_float_stale_scaler_threshold','MLP-F32: stale scaler + threshold'),
 ('mlp_int8_stale_scaler','MLP-I8: stale scaler'),
 ('mlp_int8_stale_threshold','MLP-I8: stale logit threshold'),
 ('mlp_int8_stale_scaler_threshold','MLP-I8: stale scaler + threshold'),
 ('mlp_int8_stale_input_quantization','MLP-I8: stale input scale'),
 ('mlp_int8_stale_integer_threshold_code','MLP-I8: stale threshold code'),
 ('lr_compatible_probability','LR: probability-preserving export'),
 ('lr_compatible_decision','LR: decision-preserving export'),
 ('mlp_float_compatible_first_layer','MLP-F32: first-layer conversion'),
 ('mlp_int8_compatible_requantized','MLP-I8: conversion + requantization'),
]

def style():
    plt.rcParams.update({'font.family':'DejaVu Sans','font.size':9,'axes.titlesize':10,
        'axes.labelsize':9,'xtick.labelsize':8,'ytick.labelsize':8,
        'legend.fontsize':8,'axes.spines.top':False,'axes.spines.right':False,
        'pdf.fonttype':42,'ps.fonttype':42,'savefig.dpi':300,'figure.facecolor':'white'})

def save(fig,out,name):
    for ext in ('pdf','png'):fig.savefig(out/(name+'.'+ext),bbox_inches='tight',facecolor='white')
    plt.close(fig)

def fmt_count(n):
    return '0' if n==0 else f'{n:,}'

def coverage(e,out):
    roles=['A_fit','A_cal','B_fit_added','B_cal','common_test']
    types=['normal','scanning','dos','injection','ddos','password','xss','backdoor','ransomware','mitm']
    data=np.array([[e['support']['roles'][r]['types'].get(t,0) for r in roles] for t in types])
    fig,ax=plt.subplots(figsize=(6.89,4.6),layout='constrained')
    cmap=plt.colormaps['YlGnBu'].copy();cmap.set_bad('#F2F3F4')
    im=ax.imshow(np.ma.masked_equal(data,0),norm=LogNorm(vmin=1000,vmax=11_000_000),cmap=cmap,aspect='auto')
    labels=['A fit','A calibration','B added fit','B calibration','Future test']
    ax.set_xticks(range(5),labels,fontsize=7.8);ax.set_yticks(range(10),[{'dos':'DoS','ddos':'DDoS','xss':'XSS','mitm':'Man-in-the-\nmiddle'}.get(t,t.capitalize()) for t in types])
    ax.tick_params(length=0);ax.xaxis.tick_top();ax.tick_params(axis='x',pad=9)
    for i in range(len(types)):
        for j in range(len(roles)):
            ax.text(j,i,fmt_count(data[i,j]),ha='center',va='center',fontsize=7,
                    color='white' if data[i,j]>180000 else '#263238')
    for boundary in [0.5,3.5,4.5]:ax.axhline(boundary,color='white',lw=2)
    
    cb=fig.colorbar(im,ax=ax,pad=.015,shrink=.82);cb.set_label('Retained rows (log scale)')
    save(fig,out,'science_coverage')

def models(e,out):
    row=e['evaluation']['cohorts']['all']['rows'];fig,axs=plt.subplots(1,3,figsize=(6.89,3.0),layout='constrained')
    x=np.arange(4);width=.34
    for ax,key,title,ylim in zip(axs,['recall','FPR','balanced_accuracy'],['(a) Recall','(b) FPR','(c) Balanced accuracy'],[(0,55),(0,28),(0,84)]):
        for version,offset,col in [('A',-.5,'#BBC8D2'),('B',.5,'#275D87')]:
            vals=[100*row[version+'_'+f][key] for f in FAMILIES]
            bars=ax.bar(x+offset*width,vals,width,label=version,color=col,edgecolor='white',linewidth=.4)
            for index,(b,v) in enumerate(zip(bars,vals)):
                other=100*row['A_'+FAMILIES[index]][key]
                label_y=max(v,other)+.06*ylim[1] if version=='B' and abs(v-other)<.045*ylim[1] else v+.7
                ax.text(b.get_x()+b.get_width()/2,label_y,f'{v:.1f}',ha='center',fontsize=7)
        ax.set_xticks(x,['LR','DT','MLP-\nF32','MLP-\nI8']);ax.set_ylim(*ylim);ax.set_title(title,loc='left');ax.set_ylabel('%');ax.grid(axis='y',alpha=.2);ax.set_axisbelow(True)
    axs[0].legend(title='Release',frameon=False,ncols=2,loc='upper left')
    axs[2].axhline(50,color='#5C6770',lw=.8,ls='--')
    save(fig,out,'science_models')

def ablation(e,out):
    co=e['evaluation']['cohorts']['all'];weights=['rows','frequency_cap100','vector_balanced']
    data=np.array([[100*co[w][n]['decision_disagreement'] for w in weights] for n,_ in VARIANTS])
    fig,ax=plt.subplots(figsize=(6.89,6.0),layout='constrained')
    im=ax.imshow(data,cmap='Blues',vmin=0,vmax=36,aspect='auto')
    ax.set_xticks(range(3),['Row-weighted','Cap = 100','Equal vector weight']);ax.xaxis.tick_top();ax.tick_params(length=0,pad=8)
    ax.set_yticks(range(len(VARIANTS)),[label for _,label in VARIANTS],fontsize=8)
    for i in range(len(VARIANTS)):
        for j in range(3):ax.text(j,i,f'{data[i,j]:.3f}',ha='center',va='center',color='white' if data[i,j]>19 else '#263238',fontsize=8)
    for y in [2.5,3.5,6.5,11.5]:ax.axhline(y,color='white',lw=2)
    cb=fig.colorbar(im,ax=ax,pad=.02,shrink=.8);cb.set_label('Decisions differing from complete B (%)')
    save(fig,out,'science_ablation')

def frequency(e,out):
    c=e['evaluation']['cohorts'];names=['B_mlp_int8','mlp_int8_compatible_requantized']
    groups=[('all','rows','All rows'),('all','frequency_cap100','Cap 100'),('all','vector_balanced','Equal vectors'),('remainder','rows','Outside top 20'),('top20','rows','Top 20 vectors')]
    fig,axs=plt.subplots(1,2,figsize=(6.89,3.2),layout='constrained')
    x=np.arange(len(groups));width=.34
    for ax,key,title in zip(axs,['FPR','recall'],['(a) False-positive rate','(b) Attack recall']):
        for j,(n,label,col) in enumerate(zip(names,['Complete B MLP-I8','Converted + requantized'],['#275D87','#C56A2D'])):
            vals=[100*c[co][w][n][key] for co,w,_ in groups];bars=ax.bar(x+(j-.5)*width,vals,width,label=label,color=col)
            for index,(b,v) in enumerate(zip(bars,vals)):
                co,w,_=groups[index];other=100*c[co][w][names[0]][key]
                label_y=max(v,other)+5.5 if j==1 and abs(v-other)<4 else v+.8
                ax.text(b.get_x()+b.get_width()/2,label_y,f'{v:.1f}',ha='center',fontsize=7)
        ax.set_xticks(x,[l.replace(' ','\n',1) for _,_,l in groups],fontsize=7.5);ax.set_ylabel('%');ax.set_title(title,loc='left');ax.grid(axis='y',alpha=.2);ax.set_axisbelow(True);ax.set_ylim(0,105 if key=='recall' else 85)
    axs[0].legend(frameon=False,loc='upper left',fontsize=7.7)
    save(fig,out,'science_frequency')

def temporal(e,out):
    days=sorted(e['by_day']);fig,axs=plt.subplots(1,2,figsize=(6.89,3.0),layout='constrained')
    for ax,key,title in zip(axs,['FPR','recall'],['(a) Daily false-positive rate','(b) Daily attack recall']):
        for f,label,col,marker in zip(FAMILIES,FAMILY_NAMES,COLORS,['o','s','^','D']):
            vals=[100*e['by_day'][day]['B_'+f][key] for day in days]
            ax.plot(range(len(days)),vals,marker=marker,color=col,lw=1.5,label=label,ms=5)
        ax.set_xticks(range(len(days)),[d[5:] for d in days]);ax.set_xlabel('UTC date in 2019');ax.set_ylabel('%');ax.set_title(title,loc='left');ax.grid(alpha=.2);ax.set_ylim(bottom=0)
    axs[0].legend(ncols=2,frameon=False,loc='upper left')
    save(fig,out,'science_temporal')

def tables(e,out):
    out.mkdir(parents=True,exist_ok=True);co=e['evaluation']['cohorts']['all']
    for weight,suffix in [('rows','rows'),('vector_balanced','vectors'),('frequency_cap100','cap100')]:
        lines=[r'\begin{tabular}{lrrrr}',r'\toprule',r'Pipeline & Recall (\%) & FPR (\%) & BA (\%) & Disagreement (\%) \\',r'\midrule']
        labels={v+'_'+f:v+' '+l for v in ('A','B') for f,l in zip(FAMILIES,FAMILY_NAMES)}
        labels.update(dict(VARIANTS))
        for i,n in enumerate(e['evaluation']['model_names']):
            m=co[weight][n]
            if i in (4,8,20):lines.append(r'\midrule')
            lines.append(labels[n]+' & '+' & '.join(f'{100*m[k]:.3f}' for k in ['recall','FPR','balanced_accuracy','decision_disagreement'])+r' \\')
        lines.extend([r'\bottomrule',r'\end{tabular}'])
        (out/f'science_all_{suffix}.tex').write_text('\n'.join(lines)+'\n')
    lines=[r'\begin{tabular}{lrrrr}',r'\toprule',r'Family & DDoS A & DDoS B & Unseen types A & Unseen types B \\',r'\midrule']
    for f,label in zip(FAMILIES,FAMILY_NAMES):
        vals=[e['evaluation']['cohorts'][c]['rows'][v+'_'+f]['recall']*100 for c in ['attack_type_added_in_B_fit','attack_type_unseen_in_all_fit_calibration'] for v in ['A','B']]
        lines.append(label+' & '+' & '.join(f'{v:.3f}' for v in vals)+r' \\')
    lines.extend([r'\bottomrule',r'\end{tabular}']);(out/'science_cohort_recall.tex').write_text('\n'.join(lines)+'\n')

def main():
    p=argparse.ArgumentParser();p.add_argument('--evidence',type=Path,default=HERE/'science_evidence.json');p.add_argument('--output',type=Path,default=HERE.parent/'manuscript/figures');a=p.parse_args()
    e=json.loads(a.evidence.read_text());a.output.mkdir(parents=True,exist_ok=True);style()
    for fn in [coverage,models,ablation,frequency,temporal]:fn(e,a.output)
    tables(e,a.output.parent/'tables')
    print('Generated 5 PDF/PNG figures and 4 full-precision-source tables.')

if __name__=='__main__':main()
