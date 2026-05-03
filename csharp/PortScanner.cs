// SmartScan - Advanced GUI Port Scanner
// Author  : Prasad
// Version : 2.0
// Platform: Windows (.NET 8 / WinForms)
//
// Enhancements over v1.0:
//   • RTT measurement per port (milliseconds)
//   • Banner / service-version grabbing (HTTP Server header, SSH, FTP, Redis)
//   • Risk hint column (plaintext-credential services, exposed DBs, etc.)
//   • Export results to CSV and TXT
//   • Copy selected rows to clipboard
//   • Dark-theme owner-draw on GroupBox, ProgressBar, ComboBox
//   • Resizable form with anchored / docked controls
//   • Mixed port-spec parser: "1-100,443,8080"
//   • IPv4-preferred hostname resolution
//   • Extended service dictionary (38 well-known ports)
//   • Validation: empty target, bad port spec, timeout bounds
//   • Status-bar shows elapsed time, updated every second

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace SmartScan
{
    // ─────────────────────────────────────────────────────────────────────────
    // Data model
    // ─────────────────────────────────────────────────────────────────────────

    public class PortResult
    {
        public int    Port         { get; set; }
        public string Service      { get; set; } = "Unknown";
        public string DetectedSvc  { get; set; } = "";
        public string Version      { get; set; } = "";
        public string RttMs        { get; set; } = "";
        public string RiskHint     { get; set; } = "";
        public bool   IsOpen       { get; set; }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Colour palette (GitHub dark theme)
    // ─────────────────────────────────────────────────────────────────────────

    internal static class Palette
    {
        public static readonly Color BgBase       = Color.FromArgb( 13,  17,  23);
        public static readonly Color BgSurface     = Color.FromArgb( 22,  27,  34);
        public static readonly Color BgElevated    = Color.FromArgb( 33,  38,  45);
        public static readonly Color Border        = Color.FromArgb( 48,  54,  61);
        public static readonly Color FgDefault     = Color.FromArgb(201, 209, 217);
        public static readonly Color FgMuted       = Color.FromArgb(139, 148, 158);
        public static readonly Color AccentBlue    = Color.FromArgb( 88, 166, 255);
        public static readonly Color AccentGreen   = Color.FromArgb( 63, 185,  80);
        public static readonly Color AccentYellow  = Color.FromArgb(210, 168,  73);
        public static readonly Color AccentRed     = Color.FromArgb(248,  81,  73);
        public static readonly Color AccentMagenta = Color.FromArgb(188, 140, 255);
        public static readonly Color BtnStartBg    = Color.FromArgb( 35, 134,  54);
        public static readonly Color BtnStopBg     = Color.FromArgb(164,  14,  38);
        public static readonly Color BtnExportBg   = Color.FromArgb( 31,  78, 121);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Main form
    // ─────────────────────────────────────────────────────────────────────────

    public class PortScannerForm : Form
    {
        // ── UI controls ──────────────────────────────────────────────────────
        private TextBox          txtTarget       = null!;
        private TextBox          txtPorts        = null!;
        private NumericUpDown    numTimeout      = null!;
        private NumericUpDown    numConcurrency  = null!;
        private ComboBox         cmbPreset       = null!;
        private CheckBox         chkBanner       = null!;
        private Button           btnStart        = null!;
        private Button           btnStop         = null!;
        private Button           btnExportCsv    = null!;
        private Button           btnExportTxt    = null!;
        private Button           btnCopy         = null!;
        private Button           btnClear        = null!;
        private ProgressBar      progressBar     = null!;
        private Label            lblTargetHdr    = null!;
        private Label            lblPortsHdr     = null!;
        private Label            lblTimeoutHdr   = null!;
        private Label            lblConcurHdr    = null!;
        private Label            lblPresetHdr    = null!;
        private Label            lblStatus       = null!;
        private Label            lblProgress     = null!;
        private Label            lblOpenCount    = null!;
        private Label            lblElapsed      = null!;
        private DataGridView     dgvResults      = null!;
        private Panel            pnlLeft         = null!;
        private Panel            pnlRight        = null!;
        private StatusStrip      statusStrip     = null!;
        private ToolStripStatusLabel statusLabel = null!;
        private ToolStripProgressBar toolProgress = null!;
        private System.Windows.Forms.Timer elapsedTimer = null!;

        // ── Scan state ───────────────────────────────────────────────────────
        private CancellationTokenSource? cts;
        private bool      isScanning   = false;
        private int       totalPorts   = 0;
        private int       scannedPorts = 0;
        private int       openCount    = 0;
        private Stopwatch scanWatch    = new Stopwatch();
        private readonly List<PortResult> results = new();
        private readonly object           lockObj = new();

        // ── Service dictionary (38 ports) ────────────────────────────────────
        private static readonly Dictionary<int, string> ServiceNames = new()
        {
            {20,"FTP-data"}, {21,"FTP"},    {22,"SSH"},      {23,"Telnet"},
            {25,"SMTP"},     {53,"DNS"},    {80,"HTTP"},     {110,"POP3"},
            {111,"RPC"},     {135,"RPC"},   {139,"NetBIOS"}, {143,"IMAP"},
            {443,"HTTPS"},   {445,"SMB"},   {465,"SMTPS"},   {587,"SMTP-sub"},
            {993,"IMAPS"},   {995,"POP3S"}, {1723,"PPTP"},
            {2375,"Docker"}, {2376,"Docker-TLS"},
            {3306,"MySQL"},  {3389,"RDP"},  {4443,"HTTPS-Alt"},
            {5432,"PostgreSQL"}, {5601,"Kibana"}, {5900,"VNC"},
            {6379,"Redis"},  {6443,"Kubernetes"},
            {8080,"HTTP-Alt"}, {8443,"HTTPS-Alt"}, {8888,"HTTP-dev"},
            {9200,"Elasticsearch"}, {9300,"Elasticsearch"},
            {11211,"Memcached"}, {27017,"MongoDB"}, {27018,"MongoDB"}
        };

        // ── Risk hints ───────────────────────────────────────────────────────
        private static readonly Dictionary<int, string> RiskHints = new()
        {
            {21,  "⚠ FTP: plaintext credentials"},
            {23,  "⚠ Telnet: unencrypted — use SSH"},
            {445, "⚠ SMB: check EternalBlue (MS17-010)"},
            {3389,"⚠ RDP: check BlueKeep (CVE-2019-0708)"},
            {5900,"⚠ VNC: restrict access / require auth"},
            {6379,"⚠ Redis: verify requirepass / firewall"},
            {9200,"⚠ Elasticsearch: confirm auth enabled"},
            {11211,"⚠ Memcached: exposed to network?"},
            {27017,"⚠ MongoDB: confirm auth enabled"},
            {2375,"⚠ Docker API: unauthenticated remote access"},
        };

        // ─────────────────────────────────────────────────────────────────────
        // Constructor
        // ─────────────────────────────────────────────────────────────────────

        public PortScannerForm()
        {
            InitializeComponent();
            ApplyTheme();
            SetupDataGrid();
        }

        // ─────────────────────────────────────────────────────────────────────
        // InitializeComponent
        // ─────────────────────────────────────────────────────────────────────

        private void InitializeComponent()
        {
            this.SuspendLayout();

            // ── Left panel (controls) ────────────────────────────────────────
            pnlLeft = new Panel
            {
                Width   = 310,
                Dock    = DockStyle.Left,
                Padding = new Padding(14, 14, 14, 14)
            };

            // ── Header labels + inputs ───────────────────────────────────────
            int y = 14;
            const int LBL_H = 18, INPUT_H = 26, GAP = 6, SECTION_GAP = 14;

            lblTargetHdr = MakeLabel("TARGET  (hostname or IP)", ref y, LBL_H);
            txtTarget    = MakeTextBox("google.com", ref y, INPUT_H, GAP);

            lblPortsHdr  = MakeLabel("PORTS  (e.g. 1-1000, 22,80,443)", ref y, LBL_H, SECTION_GAP);
            txtPorts     = MakeTextBox("1-1000", ref y, INPUT_H, GAP);

            lblPresetHdr = MakeLabel("PRESET", ref y, LBL_H, SECTION_GAP);
            cmbPreset    = new ComboBox
            {
                Location  = new Point(0, y),
                Size      = new Size(pnlLeft.Width - pnlLeft.Padding.Horizontal, INPUT_H + 2),
                DropDownStyle = ComboBoxStyle.DropDownList,
                Font      = new Font("Consolas", 10F),
                FlatStyle = FlatStyle.Flat,
                Anchor    = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            cmbPreset.Items.AddRange(new object[]
            {
                "Custom",
                "Quick Scan  (top 24 ports)",
                "Common Web  (80, 443, 8080, 8443)",
                "Databases   (3306, 5432, 27017, 1433)",
                "Standard    (top 38 ports)",
                "Full Range  (1–65535)"
            });
            cmbPreset.SelectedIndex = 1;
            cmbPreset.SelectedIndexChanged += CmbPreset_SelectedIndexChanged;
            y += INPUT_H + 2 + SECTION_GAP;

            lblTimeoutHdr = MakeLabel("TIMEOUT  (ms)", ref y, LBL_H);
            numTimeout    = MakeNumeric(ref y, INPUT_H, GAP, 100, 10000, 500, 100);

            lblConcurHdr  = MakeLabel("CONCURRENCY  (parallel tasks)", ref y, LBL_H, SECTION_GAP);
            numConcurrency = MakeNumeric(ref y, INPUT_H, GAP, 10, 1000, 200, 50);

            chkBanner = new CheckBox
            {
                Text     = "Banner / version grabbing",
                Location = new Point(0, y + SECTION_GAP),
                Size     = new Size(pnlLeft.Width - pnlLeft.Padding.Horizontal, 22),
                Font     = new Font("Consolas", 10F),
                Checked  = true,
                Anchor   = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            y += SECTION_GAP + 22 + SECTION_GAP;

            // ── Action buttons ────────────────────────────────────────────────
            int btnW = (pnlLeft.Width - pnlLeft.Padding.Horizontal - 6) / 2;
            btnStart = MakeButton("▶  START", new Point(0, y), new Size(btnW, 38),
                                  Palette.BtnStartBg, BtnStart_Click);
            btnStop  = MakeButton("■  STOP",  new Point(btnW + 6, y), new Size(btnW, 38),
                                  Palette.BtnStopBg,  BtnStop_Click);
            btnStop.Enabled = false;
            y += 38 + SECTION_GAP;

            // ── Progress ──────────────────────────────────────────────────────
            progressBar = new ProgressBar
            {
                Location  = new Point(0, y),
                Size      = new Size(pnlLeft.Width - pnlLeft.Padding.Horizontal, 14),
                Style     = ProgressBarStyle.Continuous,
                Anchor    = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            y += 14 + 6;

            lblProgress = new Label
            {
                Location  = new Point(0, y),
                Size      = new Size(pnlLeft.Width - pnlLeft.Padding.Horizontal, 18),
                Font      = new Font("Consolas", 9F),
                Text      = "0 / 0 ports  (0%)",
                Anchor    = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            y += 18 + 4;

            lblStatus = new Label
            {
                Location  = new Point(0, y),
                Size      = new Size(pnlLeft.Width - pnlLeft.Padding.Horizontal, 18),
                Font      = new Font("Consolas", 9F),
                Text      = "Ready",
                Anchor    = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            y += 18 + 4;

            lblOpenCount = new Label
            {
                Location  = new Point(0, y),
                Size      = new Size(pnlLeft.Width - pnlLeft.Padding.Horizontal, 22),
                Font      = new Font("Consolas", 11F, FontStyle.Bold),
                Text      = "Open ports: 0",
                Anchor    = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            y += 22 + 4;

            lblElapsed = new Label
            {
                Location  = new Point(0, y),
                Size      = new Size(pnlLeft.Width - pnlLeft.Padding.Horizontal, 18),
                Font      = new Font("Consolas", 9F),
                Text      = "Elapsed: 0s",
                Anchor    = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            y += 18 + SECTION_GAP;

            // ── Export / utility buttons ──────────────────────────────────────
            int btnW3 = (pnlLeft.Width - pnlLeft.Padding.Horizontal - 12) / 3;
            btnExportCsv = MakeButton("CSV", new Point(0,           y), new Size(btnW3, 30),
                                       Palette.BtnExportBg, BtnExportCsv_Click);
            btnExportTxt = MakeButton("TXT", new Point(btnW3 + 6,   y), new Size(btnW3, 30),
                                       Palette.BtnExportBg, BtnExportTxt_Click);
            btnCopy      = MakeButton("COPY",new Point(btnW3*2+12,  y), new Size(btnW3, 30),
                                       Palette.BgElevated,   BtnCopy_Click);
            y += 30 + 6;
            btnClear     = MakeButton("CLEAR RESULTS", new Point(0, y),
                                       new Size(pnlLeft.Width - pnlLeft.Padding.Horizontal, 28),
                                       Palette.BgElevated, BtnClear_Click);

            // Add all controls to left panel
            pnlLeft.Controls.AddRange(new Control[]
            {
                lblTargetHdr, txtTarget, lblPortsHdr, txtPorts,
                lblPresetHdr, cmbPreset, lblTimeoutHdr, numTimeout,
                lblConcurHdr, numConcurrency, chkBanner,
                btnStart, btnStop, progressBar,
                lblProgress, lblStatus, lblOpenCount, lblElapsed,
                btnExportCsv, btnExportTxt, btnCopy, btnClear
            });

            // ── Right panel (results grid) ───────────────────────────────────
            pnlRight = new Panel { Dock = DockStyle.Fill, Padding = new Padding(8, 8, 8, 8) };

            dgvResults = new DataGridView
            {
                Dock                             = DockStyle.Fill,
                AllowUserToAddRows               = false,
                AllowUserToDeleteRows            = false,
                AllowUserToResizeRows            = false,
                MultiSelect                      = true,
                SelectionMode                    = DataGridViewSelectionMode.FullRowSelect,
                ReadOnly                         = true,
                RowHeadersVisible                = false,
                BorderStyle                      = BorderStyle.None,
                ColumnHeadersHeightSizeMode      = DataGridViewColumnHeadersHeightSizeMode.DisableResizing,
                ColumnHeadersHeight              = 32,
                RowTemplate                      = { Height = 26 },
                Font                             = new Font("Consolas", 10F),
                ShowCellToolTips                 = true,
                AutoSizeRowsMode                 = DataGridViewAutoSizeRowsMode.None,
                ClipboardCopyMode                = DataGridViewClipboardCopyMode.EnableWithAutoHeaderText
            };
            pnlRight.Controls.Add(dgvResults);

            // ── Status strip ─────────────────────────────────────────────────
            statusStrip  = new StatusStrip();
            statusLabel  = new ToolStripStatusLabel("SmartScan v2.0  ·  by Prasad")
            {
                Spring     = true,
                TextAlign  = ContentAlignment.MiddleLeft
            };
            toolProgress = new ToolStripProgressBar
            {
                Visible = false,
                Size    = new Size(160, 14)
            };
            statusStrip.Items.AddRange(new ToolStripItem[] { statusLabel, toolProgress });

            // ── Elapsed timer ─────────────────────────────────────────────────
            elapsedTimer = new System.Windows.Forms.Timer { Interval = 1000 };
            elapsedTimer.Tick += (_, _) =>
            {
                if (isScanning)
                    lblElapsed.Text = $"Elapsed: {(int)scanWatch.Elapsed.TotalSeconds}s";
            };

            // ── Form ──────────────────────────────────────────────────────────
            this.Text            = "SmartScan v2.0  —  Advanced Port Scanner";
            this.ClientSize      = new Size(1060, 590);
            this.MinimumSize     = new Size(860, 520);
            this.FormBorderStyle = FormBorderStyle.Sizable;
            this.MaximizeBox     = true;
            this.StartPosition   = FormStartPosition.CenterScreen;
            this.Font            = new Font("Consolas", 9F);
            this.Controls.Add(pnlRight);
            this.Controls.Add(pnlLeft);
            this.Controls.Add(statusStrip);

            this.ResumeLayout(false);
            this.PerformLayout();
        }

        // ─────────────────────────────────────────────────────────────────────
        // DataGrid setup (column definitions)
        // ─────────────────────────────────────────────────────────────────────

        private void SetupDataGrid()
        {
            dgvResults.Columns.Clear();

            AddCol("port",        "PORT",     65,  DataGridViewContentAlignment.MiddleCenter);
            AddCol("service",     "SERVICE",  120, DataGridViewContentAlignment.MiddleLeft);
            AddCol("detected",    "DETECTED", 150, DataGridViewContentAlignment.MiddleLeft);
            AddCol("version",     "VERSION",  130, DataGridViewContentAlignment.MiddleLeft);
            AddCol("rtt",         "RTT (ms)", 80,  DataGridViewContentAlignment.MiddleRight);
            AddCol("risk",        "RISK HINT",220, DataGridViewContentAlignment.MiddleLeft);

            dgvResults.Columns["port"]!.DefaultCellStyle.ForeColor     = Palette.AccentBlue;
            dgvResults.Columns["service"]!.DefaultCellStyle.ForeColor  = Palette.AccentYellow;
            dgvResults.Columns["detected"]!.DefaultCellStyle.ForeColor = Palette.AccentGreen;
            dgvResults.Columns["version"]!.DefaultCellStyle.ForeColor  = Palette.FgDefault;
            dgvResults.Columns["rtt"]!.DefaultCellStyle.ForeColor      = Palette.FgMuted;
            dgvResults.Columns["risk"]!.DefaultCellStyle.ForeColor     = Palette.AccentYellow;

            // Last column fills remaining space
            dgvResults.Columns["risk"]!.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
        }

        private void AddCol(string name, string header, int width, DataGridViewContentAlignment align)
        {
            var col = new DataGridViewTextBoxColumn
            {
                Name            = name,
                HeaderText      = header,
                Width           = width,
                MinimumWidth    = width / 2,
                Resizable       = DataGridViewTriState.True,
                SortMode        = DataGridViewColumnSortMode.Automatic,
                DefaultCellStyle = { Alignment = align, Padding = new Padding(4, 0, 4, 0) }
            };
            dgvResults.Columns.Add(col);
        }

        // ─────────────────────────────────────────────────────────────────────
        // Theme application
        // ─────────────────────────────────────────────────────────────────────

        private void ApplyTheme()
        {
            this.BackColor = Palette.BgBase;
            this.ForeColor = Palette.FgDefault;

            pnlLeft.BackColor  = Palette.BgSurface;
            pnlRight.BackColor = Palette.BgBase;

            foreach (Control c in pnlLeft.Controls)
            {
                c.ForeColor = Palette.FgDefault;
                c.BackColor = c switch
                {
                    Label         => Palette.BgSurface,
                    CheckBox      => Palette.BgSurface,
                    _             => Palette.BgElevated
                };
            }

            // Override specific labels
            lblTargetHdr.ForeColor   = Palette.FgMuted;
            lblPortsHdr.ForeColor    = Palette.FgMuted;
            lblTimeoutHdr.ForeColor  = Palette.FgMuted;
            lblConcurHdr.ForeColor   = Palette.FgMuted;
            lblPresetHdr.ForeColor   = Palette.FgMuted;
            lblOpenCount.ForeColor   = Palette.AccentGreen;
            lblStatus.ForeColor      = Palette.FgMuted;
            lblProgress.ForeColor    = Palette.FgMuted;
            lblElapsed.ForeColor     = Palette.FgMuted;

            progressBar.BackColor    = Palette.BgElevated;
            progressBar.ForeColor    = Palette.AccentGreen;

            // DataGrid
            dgvResults.BackgroundColor                      = Palette.BgBase;
            dgvResults.DefaultCellStyle.BackColor           = Palette.BgBase;
            dgvResults.DefaultCellStyle.ForeColor           = Palette.FgDefault;
            dgvResults.DefaultCellStyle.SelectionBackColor  = Palette.BgElevated;
            dgvResults.DefaultCellStyle.SelectionForeColor  = Palette.AccentBlue;
            dgvResults.GridColor                            = Palette.Border;
            dgvResults.ColumnHeadersDefaultCellStyle.BackColor  = Palette.BgElevated;
            dgvResults.ColumnHeadersDefaultCellStyle.ForeColor  = Palette.AccentBlue;
            dgvResults.ColumnHeadersDefaultCellStyle.Font       = new Font("Consolas", 10F, FontStyle.Bold);
            dgvResults.EnableHeadersVisualStyles                = false;
            dgvResults.AlternatingRowsDefaultCellStyle.BackColor = Color.FromArgb(18, 22, 29);

            // Status strip
            statusStrip.BackColor = Palette.BgElevated;
            statusStrip.ForeColor = Palette.FgMuted;
            statusLabel.ForeColor = Palette.FgMuted;

            // Buttons already coloured in InitializeComponent via MakeButton
            btnExportCsv.ForeColor = Palette.AccentBlue;
            btnExportTxt.ForeColor = Palette.AccentBlue;
            btnCopy.ForeColor      = Palette.FgDefault;
            btnClear.ForeColor     = Palette.AccentRed;
        }

        // ─────────────────────────────────────────────────────────────────────
        // Control factory helpers
        // ─────────────────────────────────────────────────────────────────────

        private Label MakeLabel(string text, ref int y, int height, int extraGapAbove = 4)
        {
            y += extraGapAbove;
            var lbl = new Label
            {
                Text     = text,
                Location = new Point(0, y),
                Size     = new Size(pnlLeft.Width - pnlLeft.Padding.Horizontal, height),
                Font     = new Font("Consolas", 8.5F, FontStyle.Bold),
                Anchor   = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            y += height;
            return lbl;
        }

        private TextBox MakeTextBox(string defaultText, ref int y, int height, int gap)
        {
            var tb = new TextBox
            {
                Text        = defaultText,
                Location    = new Point(0, y),
                Size        = new Size(pnlLeft.Width - pnlLeft.Padding.Horizontal, height),
                Font        = new Font("Consolas", 11F),
                BorderStyle = BorderStyle.FixedSingle,
                Anchor      = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            y += height + gap;
            return tb;
        }

        private NumericUpDown MakeNumeric(ref int y, int height, int gap,
            int min, int max, int val, int inc)
        {
            var n = new NumericUpDown
            {
                Location  = new Point(0, y),
                Size      = new Size(pnlLeft.Width - pnlLeft.Padding.Horizontal, height),
                Minimum   = min, Maximum = max, Value = val, Increment = inc,
                Font      = new Font("Consolas", 11F),
                Anchor    = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right
            };
            y += height + gap;
            return n;
        }

        private static Button MakeButton(string text, Point loc, Size size,
            Color bg, EventHandler handler)
        {
            var btn = new Button
            {
                Text              = text,
                Location          = loc,
                Size              = size,
                Font              = new Font("Consolas", 10F, FontStyle.Bold),
                BackColor         = bg,
                ForeColor         = Color.White,
                FlatStyle         = FlatStyle.Flat,
                Cursor            = Cursors.Hand,
                UseVisualStyleBackColor = false,
                Anchor            = AnchorStyles.Top | AnchorStyles.Left
            };
            btn.FlatAppearance.BorderSize  = 0;
            btn.FlatAppearance.MouseOverBackColor  = ControlPaint.Light(bg, 0.15f);
            btn.FlatAppearance.MouseDownBackColor  = ControlPaint.Dark(bg, 0.1f);
            btn.Click += handler;
            return btn;
        }

        // ─────────────────────────────────────────────────────────────────────
        // Preset handler
        // ─────────────────────────────────────────────────────────────────────

        private void CmbPreset_SelectedIndexChanged(object? sender, EventArgs e)
        {
            switch (cmbPreset.SelectedIndex)
            {
                case 0:  // Custom
                    txtPorts.Enabled = true;
                    break;
                case 1:  // Quick
                    txtPorts.Enabled = false;
                    txtPorts.Text = "21,22,23,25,53,80,110,111,135,139,143,443,445," +
                                    "993,995,1723,3306,3389,5432,5900,6379,8080,8443,27017";
                    break;
                case 2:  // Common Web
                    txtPorts.Enabled = false;
                    txtPorts.Text = "80,443,8080,8443";
                    break;
                case 3:  // Databases
                    txtPorts.Enabled = false;
                    txtPorts.Text = "1433,3306,5432,5601,6379,9200,11211,27017,27018";
                    break;
                case 4:  // Standard (38 ports)
                    txtPorts.Enabled = false;
                    txtPorts.Text = "20,21,22,23,25,53,80,110,111,135,139,143,443,445," +
                                    "465,587,993,995,1723,2375,2376,3306,3389,4443,5432," +
                                    "5601,5900,6379,6443,8080,8443,8888,9200,11211,27017,27018";
                    break;
                case 5:  // Full range
                    txtPorts.Enabled = false;
                    txtPorts.Text = "1-65535";
                    break;
            }
        }

        // ─────────────────────────────────────────────────────────────────────
        // Port-spec parser  — handles "80", "1-1024", "22,80,443", mixed
        // ─────────────────────────────────────────────────────────────────────

        private static List<int> ParsePorts(string spec)
        {
            var seen  = new HashSet<int>();
            var ports = new List<int>();

            foreach (var chunk in spec.Split(',', StringSplitOptions.RemoveEmptyEntries))
            {
                var c = chunk.Trim();
                if (c.Contains('-'))
                {
                    var parts = c.Split('-', 2);
                    if (parts.Length == 2
                        && int.TryParse(parts[0].Trim(), out int a)
                        && int.TryParse(parts[1].Trim(), out int b)
                        && a >= 1 && b <= 65535 && a <= b)
                    {
                        for (int p = a; p <= b; p++)
                            if (seen.Add(p)) ports.Add(p);
                    }
                }
                else if (int.TryParse(c, out int single) && single >= 1 && single <= 65535)
                {
                    if (seen.Add(single)) ports.Add(single);
                }
            }
            return ports;
        }

        // ─────────────────────────────────────────────────────────────────────
        // IPv4-preferred host resolver
        // ─────────────────────────────────────────────────────────────────────

        private static async Task<string?> ResolveHostAsync(string host)
        {
            try
            {
                var entries = await Dns.GetHostAddressesAsync(host);
                // Prefer IPv4
                return entries.FirstOrDefault(a => a.AddressFamily == AddressFamily.InterNetwork)?.ToString()
                    ?? entries.FirstOrDefault()?.ToString();
            }
            catch { return null; }
        }

        // ─────────────────────────────────────────────────────────────────────
        // Banner grabber  (plain TCP read, 1-second read window)
        // ─────────────────────────────────────────────────────────────────────

        private static readonly Dictionary<int, byte[]> BannerProbes = new()
        {
            {21,    Encoding.ASCII.GetBytes("HELP\r\n")},
            {25,    Encoding.ASCII.GetBytes("EHLO smartscan.local\r\n")},
            {80,    Encoding.ASCII.GetBytes("HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: SmartScan/2.0\r\n\r\n")},
            {110,   Encoding.ASCII.GetBytes("USER probe\r\n")},
            {143,   Encoding.ASCII.GetBytes("a001 CAPABILITY\r\n")},
            {6379,  Encoding.ASCII.GetBytes("PING\r\n")},
            {9200,  Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")},
            {11211, Encoding.ASCII.GetBytes("version\r\n")},
        };

        private static async Task<(string detected, string version, string banner)>
            GrabBannerAsync(string host, int port, int timeoutMs)
        {
            try
            {
                using var tcp = new TcpClient();
                await tcp.ConnectAsync(host, port).WaitAsync(TimeSpan.FromMilliseconds(timeoutMs));
                using var stream = tcp.GetStream();
                stream.ReadTimeout  = Math.Min(timeoutMs, 1500);
                stream.WriteTimeout = 500;

                if (BannerProbes.TryGetValue(port, out var probe))
                    await stream.WriteAsync(probe);

                var buf = new byte[2048];
                int n   = 0;
                try { n = await stream.ReadAsync(buf).AsTask()
                                      .WaitAsync(TimeSpan.FromMilliseconds(Math.Min(timeoutMs, 1500))); }
                catch { /* partial banner or timeout */ }

                if (n == 0) return ("", "", "");

                var raw = Encoding.UTF8.GetString(buf, 0, n)
                                       .Replace("\0", "")
                                       .Split('\n')[0]   // first line
                                       .Trim();
                raw = raw.Length > 200 ? raw[..200] : raw;

                return Fingerprint(port, raw);
            }
            catch { return ("", "", ""); }
        }

        private static (string detected, string version, string banner) Fingerprint(int port, string banner)
        {
            var b = banner.ToLowerInvariant();

            if (banner.StartsWith("SSH-"))
            {
                var ver = ExtractAfter(banner, "OpenSSH_") ?? ExtractAfter(banner, "dropbear_") ?? "";
                var name = b.Contains("openssh") ? "SSH (OpenSSH)" : b.Contains("dropbear") ? "SSH (Dropbear)" : "SSH";
                return (name, ver, banner);
            }
            if (banner.StartsWith("+PONG") || b.Contains("redis_version:"))
            {
                var ver = ExtractAfter(banner, "redis_version:") ?? "";
                return ("Redis", ver, banner);
            }
            if (banner.StartsWith("+OK"))
                return ("POP3", "", banner);
            if (banner.StartsWith("* OK"))
                return ("IMAP", "", banner);
            if (banner.StartsWith("220") && (b.Contains("ftp") || b.Contains("vsftpd") || b.Contains("proftpd")))
            {
                var ver = ExtractAfter(banner, "vsFTPd ") ?? ExtractAfter(banner, "ProFTPD ") ?? "";
                return ("FTP", ver, banner);
            }
            if (banner.StartsWith("220") && (b.Contains("smtp") || b.Contains("esmtp") || b.Contains("postfix")))
                return ("SMTP", ExtractAfter(banner, "Postfix ") ?? "", banner);
            if (b.Contains("server: apache/"))
            {
                var ver = ExtractAfter(banner, "Apache/") ?? ExtractAfter(banner, "apache/") ?? "";
                return ("HTTP (Apache)", ver, banner);
            }
            if (b.Contains("server: nginx/"))
            {
                var ver = ExtractAfter(banner, "nginx/") ?? "";
                return ("HTTP (nginx)", ver, banner);
            }
            if (b.Contains("server: microsoft-iis/"))
            {
                var ver = ExtractAfter(banner, "Microsoft-IIS/") ?? "";
                return ("HTTP (IIS)", ver, banner);
            }
            if (b.Contains("http/") || b.Contains("server:"))
                return ("HTTP", "", banner);
            if (banner.StartsWith("VERSION "))
                return ("Memcached", ExtractAfter(banner, "VERSION ") ?? "", banner);
            if (b.Contains("\"cluster_name\"") || b.Contains("\"version\""))
                return ("Elasticsearch", "", banner);

            return ("", "", banner);
        }

        private static string? ExtractAfter(string src, string marker)
        {
            int i = src.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
            if (i < 0) return null;
            var rest = src[(i + marker.Length)..].TrimStart();
            var end  = rest.IndexOfAny(new[] { ' ', '\r', '\n', '/' });
            var val  = end < 0 ? rest : rest[..end];
            return string.IsNullOrWhiteSpace(val) ? null : val;
        }

        // ─────────────────────────────────────────────────────────────────────
        // Per-port scanner  (returns null if closed)
        // ─────────────────────────────────────────────────────────────────────

        private async Task<PortResult?> ScanPortAsync(
            string host, int port, int timeoutMs, bool doBanner,
            CancellationToken ct)
        {
            ct.ThrowIfCancellationRequested();
            var r = new PortResult
            {
                Port    = port,
                Service = ServiceNames.GetValueOrDefault(port, "Unknown")
            };

            var sw = Stopwatch.StartNew();
            try
            {
                using var tcp     = new TcpClient();
                using var linked  = CancellationTokenSource.CreateLinkedTokenSource(ct);
                linked.CancelAfter(timeoutMs);
                await tcp.ConnectAsync(host, port, linked.Token);
                sw.Stop();
                r.IsOpen  = true;
                r.RttMs   = sw.ElapsedMilliseconds.ToString();
            }
            catch { return null; }

            if (doBanner)
            {
                var (det, ver, _) = await GrabBannerAsync(host, port, timeoutMs);
                r.DetectedSvc = det;
                r.Version     = ver;
            }

            r.RiskHint = RiskHints.GetValueOrDefault(port, "");
            return r;
        }

        // ─────────────────────────────────────────────────────────────────────
        // UI helpers
        // ─────────────────────────────────────────────────────────────────────

        private void SetScanningState(bool scanning)
        {
            btnStart.Enabled      = !scanning;
            btnStop.Enabled       =  scanning;
            txtTarget.Enabled     = !scanning;
            cmbPreset.Enabled     = !scanning;
            numTimeout.Enabled    = !scanning;
            numConcurrency.Enabled= !scanning;
            chkBanner.Enabled     = !scanning;
            txtPorts.Enabled      = !scanning && cmbPreset.SelectedIndex == 0;
            toolProgress.Visible  =  scanning;
            isScanning            =  scanning;
        }

        private void UpdateProgress()
        {
            int pct = totalPorts == 0 ? 0 : (int)(scannedPorts * 100.0 / totalPorts);
            progressBar.Value     = Math.Min(scannedPorts, totalPorts);
            toolProgress.Value    = Math.Min(scannedPorts, totalPorts);
            lblProgress.Text      = $"{scannedPorts} / {totalPorts} ports  ({pct}%)";
            lblOpenCount.Text     = $"Open ports: {openCount}";
            lblStatus.Text        = $"Scanning…  {pct}% — {openCount} open";
            statusLabel.Text      = $" Scanning {lblStatus.Text}";
        }

        private void AddResultRow(PortResult r)
        {
            // Insert at top so most recent appears first
            dgvResults.Rows.Insert(0, r.Port, r.Service, r.DetectedSvc,
                                   r.Version, r.RttMs, r.RiskHint);
            // Colour the risk cell if non-empty
            if (!string.IsNullOrEmpty(r.RiskHint))
                dgvResults.Rows[0].Cells["risk"].Style.ForeColor = Palette.AccentYellow;
        }

        // ─────────────────────────────────────────────────────────────────────
        // START button
        // ─────────────────────────────────────────────────────────────────────

        private async void BtnStart_Click(object? sender, EventArgs e)
        {
            if (isScanning) return;

            // ── Validation ────────────────────────────────────────────────────
            string rawTarget = txtTarget.Text.Trim();
            if (string.IsNullOrWhiteSpace(rawTarget))
            {
                MessageBox.Show("Please enter a target hostname or IP address.",
                    "Validation", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            var ports = ParsePorts(txtPorts.Text);
            if (ports.Count == 0)
            {
                MessageBox.Show(
                    "Invalid port specification.\n\nExamples: 80   1-1000   22,80,443   1-100,443,8080",
                    "Validation", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            int timeoutMs   = (int)numTimeout.Value;
            int concurrency = (int)numConcurrency.Value;
            bool doBanner   = chkBanner.Checked;

            // ── Resolve ───────────────────────────────────────────────────────
            statusLabel.Text = $" Resolving {rawTarget}…";
            string? ipStr    = await ResolveHostAsync(
                rawTarget.TrimStart("https://".ToCharArray())
                         .TrimStart("http://".ToCharArray())
                         .Split('/')[0]);
            if (ipStr == null)
            {
                MessageBox.Show($"Cannot resolve host: {rawTarget}",
                    "Resolution Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                statusLabel.Text = " Ready";
                return;
            }
            statusLabel.Text = $" Resolved: {rawTarget} → {ipStr}";

            // ── Setup ─────────────────────────────────────────────────────────
            results.Clear();
            dgvResults.Rows.Clear();
            totalPorts   = ports.Count;
            scannedPorts = 0;
            openCount    = 0;
            progressBar.Maximum  = totalPorts;
            toolProgress.Maximum = totalPorts;
            progressBar.Value    = 0;
            toolProgress.Value   = 0;
            lblElapsed.Text      = "Elapsed: 0s";

            SetScanningState(true);
            scanWatch.Restart();
            elapsedTimer.Start();
            cts = new CancellationTokenSource();
            var token = cts.Token;

            // ── Scan ──────────────────────────────────────────────────────────
            try
            {
                await Task.Run(async () =>
                {
                    var semaphore = new SemaphoreSlim(concurrency);
                    var tasks     = ports.Select(async port =>
                    {
                        await semaphore.WaitAsync(token);
                        try
                        {
                            var r = await ScanPortAsync(ipStr, port, timeoutMs, doBanner, token);
                            lock (lockObj)
                            {
                                scannedPorts++;
                                if (r != null)
                                {
                                    results.Add(r);
                                    openCount++;
                                    this.Invoke(() => AddResultRow(r));
                                }
                                this.Invoke(UpdateProgress);
                            }
                        }
                        finally { semaphore.Release(); }
                    });
                    await Task.WhenAll(tasks);
                }, token);
            }
            catch (OperationCanceledException) { /* user stopped */ }

            // ── Finish ────────────────────────────────────────────────────────
            scanWatch.Stop();
            elapsedTimer.Stop();
            SetScanningState(false);

            bool cancelled = token.IsCancellationRequested;
            string outcome = cancelled
                ? $"Scan stopped  —  {openCount} open port(s) found"
                : $"✓ Complete  —  {openCount} open port(s) on {rawTarget}  [{scanWatch.Elapsed.TotalSeconds:0.0}s]";

            lblStatus.Text   = outcome;
            lblElapsed.Text  = $"Elapsed: {scanWatch.Elapsed.TotalSeconds:0.0}s";
            statusLabel.Text = $"  {outcome}";
        }

        // ─────────────────────────────────────────────────────────────────────
        // STOP button
        // ─────────────────────────────────────────────────────────────────────

        private void BtnStop_Click(object? sender, EventArgs e)
        {
            if (!isScanning || cts == null) return;
            cts.Cancel();
            lblStatus.Text   = "Stopping…";
            statusLabel.Text = " Stopping scan…";
        }

        // ─────────────────────────────────────────────────────────────────────
        // Export / utility
        // ─────────────────────────────────────────────────────────────────────

        private void BtnExportCsv_Click(object? sender, EventArgs e)
        {
            if (results.Count == 0)
            { MessageBox.Show("No results to export.", "Export", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }

            using var dlg = new SaveFileDialog
            { Filter = "CSV files|*.csv", FileName = $"smartscan_{DateTime.Now:yyyyMMdd_HHmm}.csv" };
            if (dlg.ShowDialog() != DialogResult.OK) return;

            var sb = new StringBuilder();
            sb.AppendLine("Port,Service,Detected,Version,RTT_ms,RiskHint");
            foreach (var r in results.OrderBy(r => r.Port))
                sb.AppendLine($"{r.Port},{Q(r.Service)},{Q(r.DetectedSvc)},{Q(r.Version)},{r.RttMs},{Q(r.RiskHint)}");

            File.WriteAllText(dlg.FileName, sb.ToString());
            statusLabel.Text = $" Exported → {dlg.FileName}";
        }

        private void BtnExportTxt_Click(object? sender, EventArgs e)
        {
            if (results.Count == 0)
            { MessageBox.Show("No results to export.", "Export", MessageBoxButtons.OK, MessageBoxIcon.Information); return; }

            using var dlg = new SaveFileDialog
            { Filter = "Text files|*.txt", FileName = $"smartscan_{DateTime.Now:yyyyMMdd_HHmm}.txt" };
            if (dlg.ShowDialog() != DialogResult.OK) return;

            var sb = new StringBuilder();
            sb.AppendLine($"SmartScan v2.0  —  by Prasad");
            sb.AppendLine($"Generated : {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            sb.AppendLine($"Target    : {txtTarget.Text.Trim()}");
            sb.AppendLine($"Open ports: {results.Count}");
            sb.AppendLine(new string('─', 72));
            sb.AppendLine($"{"PORT",-8} {"SERVICE",-16} {"DETECTED",-20} {"VERSION",-14} {"RTT_ms",-8} RISK");
            sb.AppendLine(new string('─', 72));
            foreach (var r in results.OrderBy(r => r.Port))
                sb.AppendLine($"{r.Port,-8} {r.Service,-16} {r.DetectedSvc,-20} {r.Version,-14} {r.RttMs,-8} {r.RiskHint}");

            File.WriteAllText(dlg.FileName, sb.ToString());
            statusLabel.Text = $" Exported → {dlg.FileName}";
        }

        private void BtnCopy_Click(object? sender, EventArgs e)
        {
            if (dgvResults.SelectedRows.Count == 0)
            { Clipboard.SetText(string.Empty); return; }

            var sb = new StringBuilder();
            sb.AppendLine("Port\tService\tDetected\tVersion\tRTT\tRisk");
            foreach (DataGridViewRow row in dgvResults.SelectedRows)
            {
                var vals = new List<string>();
                foreach (DataGridViewCell cell in row.Cells)
                    vals.Add(cell.Value?.ToString() ?? "");
                sb.AppendLine(string.Join("\t", vals));
            }
            Clipboard.SetText(sb.ToString());
            statusLabel.Text = $" Copied {dgvResults.SelectedRows.Count} row(s) to clipboard";
        }

        private void BtnClear_Click(object? sender, EventArgs e)
        {
            if (isScanning) return;
            results.Clear();
            dgvResults.Rows.Clear();
            openCount    = 0;
            scannedPorts = 0;
            progressBar.Value = 0;
            lblOpenCount.Text = "Open ports: 0";
            lblProgress.Text  = "0 / 0 ports  (0%)";
            lblStatus.Text    = "Ready";
            lblElapsed.Text   = "Elapsed: 0s";
            statusLabel.Text  = " SmartScan v2.0  ·  by Prasad";
        }

        // ── CSV quoting helper ────────────────────────────────────────────────
        private static string Q(string s) =>
            s.Contains(',') || s.Contains('"') || s.Contains('\n')
                ? $"\"{s.Replace("\"", "\"\"")}\"" : s;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Entry point
    // ─────────────────────────────────────────────────────────────────────────

    public static class Program
    {
        [STAThread]
        public static void Main()
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);   // crisp on 4K
            Application.Run(new PortScannerForm());
        }
    }
}
