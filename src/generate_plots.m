function generate_plots(sim, beaconResult, arpResult, fusedResult, net)
%% IEEE-Quality Figures for Paper and PPT (Windows / Octave Safe)

% ===================== OUTPUT DIRECTORY =====================
outDir = fullfile(pwd,'results');
if ~exist(outDir,'dir')
    mkdir(outDir);
end

t  = sim.time;
FS = 11;
LW = 1.6;

colorNorm   = [0.18 0.55 0.34];
colorAtk    = [0.85 0.20 0.20];
colorDetect = [0.12 0.47 0.71];

attackShade = [1 0.88 0.88];

%% Helper: shade attack window
    function shadeAttack()
        yl = ylim;
        fill([net.AttackStart_s net.AttackEnd_s net.AttackEnd_s net.AttackStart_s], ...
             [yl(1) yl(1) yl(2) yl(2)], attackShade, ...
             'EdgeColor','none','FaceAlpha',0.4);
    end

%% ===================== FIGURE 1 =====================
fig1 = figure('Name','Fig1_ARP_Traffic');
plot(t, sim.arpRate,'LineWidth',LW); hold on;
plot(t, arpResult.arpThreshold,'--','LineWidth',LW);
shadeAttack();
xlabel('Time (s)'); ylabel('ARP packets/s');
title('ARP Traffic Rate vs Time');
grid on;
saveas(fig1, fullfile(outDir,'Fig1_ARP_Traffic.png'));

%% ===================== FIGURE 2 =====================
fig2 = figure('Name','Fig2_IPMAC_Conflict');
area(t, double(sim.ipMacConflict)*2,'FaceAlpha',0.5); hold on;
stem(t(arpResult.arpDetected), ones(sum(arpResult.arpDetected),1),'r');
xlabel('Time (s)'); ylabel('Detection Flag');
title('IP–MAC Conflict Detection');
grid on;
saveas(fig2, fullfile(outDir,'Fig2_IPMAC_Conflict.png'));

%% ===================== FIGURE 3 =====================
fig3 = figure('Name','Fig3_Beacon_FP');
subplot(2,1,1);
bar(t, sim.legitBeacons); hold on;
bar(t,-sim.rogueBeacons);
title('Beacon Frames');
grid on;

subplot(2,1,2);
plot(t, beaconResult.score,'LineWidth',LW); hold on;
yline(beaconResult.threshold,'r--');
shadeAttack();
title('Beacon Anomaly Score');
grid on;
saveas(fig3, fullfile(outDir,'Fig3_Beacon_Fingerprint.png'));

%% ===================== FIGURE 4 =====================
fig4 = figure('Name','Fig4_Timeline');
plot(t, fusedResult.stage1,'b--','LineWidth',1.5); hold on;
plot(t, fusedResult.stage2,'r-.','LineWidth',1.5);
plot(t, fusedResult.fused,'k','LineWidth',2);
legend('Stage-1','Stage-2','Fused');
xlabel('Time (s)'); ylabel('Detection');
title('Dual-Stage Detection Timeline');
grid on;
saveas(fig4, fullfile(outDir,'Fig4_Detection_Timeline.png'));

%% ===================== FIGURE 5 =====================
fig5 = figure('Name','Fig5_Performance');
metrics = [fusedResult.Accuracy fusedResult.Precision ...
           fusedResult.Recall fusedResult.F1];
bar(metrics);
set(gca,'XTickLabel',{'Acc','Prec','Recall','F1'});
ylim([0 1]);
title('Performance Metrics');
grid on;
saveas(fig5, fullfile(outDir,'Fig5_Performance.png'));

%% ===================== FIGURE 6 =====================
fig6 = figure('Name','Fig6_ROC');
plot(fusedResult.rocFPR, fusedResult.rocTPR,'LineWidth',LW); hold on;
plot([0 1],[0 1],'k--');
xlabel('FPR'); ylabel('TPR');
title('ROC Curve');
grid on;
saveas(fig6, fullfile(outDir,'Fig6_ROC.png'));

%% ===================== FIGURE 7 =====================
fig7 = figure('Name','Fig7_Confusion');
CM = [fusedResult.TP fusedResult.FN; fusedResult.FP fusedResult.TN];
imagesc(CM); colorbar;
text(1,1,num2str(CM(1,1)),'HorizontalAlignment','center','Color','w');
text(2,1,num2str(CM(1,2)),'HorizontalAlignment','center','Color','w');
text(1,2,num2str(CM(2,1)),'HorizontalAlignment','center','Color','w');
text(2,2,num2str(CM(2,2)),'HorizontalAlignment','center','Color','w');
title('Confusion Matrix');
saveas(fig7, fullfile(outDir,'Fig7_Confusion.png'));

fprintf('\n? All 7 figures generated and saved in /results folder\n');
end
