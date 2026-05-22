package com.example.analyzer

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.runtime.livedata.observeAsState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.filled.Science
import androidx.compose.material.icons.filled.Analytics
import androidx.compose.material.icons.filled.History
import androidx.compose.material.icons.filled.UploadFile
import androidx.compose.material.icons.filled.FolderZip
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.DeleteSweep
import androidx.compose.material.icons.filled.LayersClear
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.DoubleArrow
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.viewmodel.compose.viewModel
import java.text.DecimalFormat
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AnalyzerAppScreen(
    viewModel: AnalyzerViewModel = viewModel()
) {
    val uiState by viewModel.uiState.collectAsState()
    val statusText by viewModel.statusText.collectAsState()
    val savedReports by viewModel.savedReports.observeAsState(emptyList())
    val viewingFinding by viewModel.viewingFinding.collectAsState()

    val context = LocalContext.current

    // Set up file selection launcher
    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri: Uri? ->
        uri?.let { viewModel.analyzeFile(it) }
    }

    var activeTab by remember { mutableStateOf(0) } // 0: Analyze / Findings, 1: History

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Icon(
                            imageVector = Icons.Filled.Science,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.padding(end = 8.dp)
                        )
                        Column {
                            Text(
                                text = "محلل APK و DEX",
                                fontWeight = FontWeight.Bold,
                                fontSize = 18.sp
                            )
                            Text(
                                text = "أدوات التحقق من المنطق الاستدلالي",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surfaceColorAtElevation(3.dp)
                )
            )
        },
        bottomBar = {
            NavigationBar {
                NavigationBarItem(
                    selected = activeTab == 0,
                    onClick = { activeTab = 0 },
                    icon = { Icon(Icons.Default.Analytics, contentDescription = "Parser") },
                    label = { Text("محرك التحليل") }
                )
                NavigationBarItem(
                    selected = activeTab == 1,
                    onClick = { activeTab = 1 },
                    icon = { Icon(Icons.Default.History, contentDescription = "History") },
                    label = { Text("فهرس البيانات") }
                )
                NavigationBarItem(
                    selected = activeTab == 2,
                    onClick = { activeTab = 2 },
                    icon = { Icon(Icons.Default.Settings, contentDescription = "Settings") },
                    label = { Text("الإعدادات") }
                )
            }
        }
    ) { paddingValues ->
        Box(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .background(MaterialTheme.colorScheme.background)
        ) {
            when (activeTab) {
                0 -> {
                    // Core scanning workspace
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(16.dp)
                    ) {
                        // Quick file load strip
                        Card(
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.3f)
                            ),
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(bottom = 16.dp)
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(16.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = "إعدادات workspace المستهدف",
                                        fontWeight = FontWeight.Bold,
                                        style = MaterialTheme.typography.titleMedium
                                    )
                                    Text(
                                        text = "استيراد أي ملف APK أو ملف ثنائي .dex (يتم فهرسة ملفات classes2.dex... تلقائيًا)",
                                        fontSize = 12.sp,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                                Button(
                                    onClick = { filePickerLauncher.launch("*/*") },
                                    shape = RoundedCornerShape(8.dp)
                                ) {
                                    Icon(Icons.Default.UploadFile, contentDescription = null, modifier = Modifier.size(18.dp))
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("تحميل الملف")
                                }
                            }
                        }

                        // State Renderings
                        when (val state = uiState) {
                            is AnalysisUiState.Idle -> {
                                Box(
                                    modifier = Modifier
                                        .weight(1f)
                                        .fillMaxWidth(),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Column(
                                        horizontalAlignment = Alignment.CenterHorizontally,
                                        verticalArrangement = Arrangement.Center
                                    ) {
                                        Icon(
                                            imageVector = Icons.Default.FolderZip,
                                            contentDescription = null,
                                            modifier = Modifier.size(72.dp),
                                            tint = MaterialTheme.colorScheme.primary.copy(alpha = 0.6f)
                                        )
                                        Spacer(modifier = Modifier.height(16.dp))
                                        Text(
                                            text = "لم يتم تحميل ملف للتحليل الثابت",
                                            fontWeight = FontWeight.Bold,
                                            style = MaterialTheme.typography.titleMedium
                                        )
                                        Spacer(modifier = Modifier.height(8.dp))
                                        Text(
                                            text = "اضغط على زر 'تحميل الملف' لاستخراج جداول الشيفرة",
                                            fontSize = 13.sp,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                        Spacer(modifier = Modifier.height(24.dp))
                                        Button(
                                            onClick = { filePickerLauncher.launch("*/*") }
                                        ) {
                                            Text("اختر ملفًا الآن")
                                        }
                                    }
                                }
                            }
                            is AnalysisUiState.Loading -> {
                                Box(
                                    modifier = Modifier
                                        .weight(1f)
                                        .fillMaxWidth(),
                                    contentAlignment = Alignment.Center
                                ) {
                                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                        CircularProgressIndicator(modifier = Modifier.size(48.dp))
                                        Spacer(modifier = Modifier.height(24.dp))
                                        Text(
                                            text = "Decompiling & Deobfuscating bytecode...",
                                            fontWeight = FontWeight.Bold,
                                            style = MaterialTheme.typography.titleMedium
                                        )
                                        Spacer(modifier = Modifier.height(8.dp))
                                        Text(
                                            text = statusText,
                                            style = MaterialTheme.typography.labelMedium,
                                            color = MaterialTheme.colorScheme.secondary
                                        )
                                        Spacer(modifier = Modifier.height(16.dp))
                                        Text(
                                            text = "Processing linear structural signatures in background",
                                            fontSize = 12.sp,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }
                            }
                            is AnalysisUiState.Error -> {
                                Card(
                                    colors = CardDefaults.cardColors(
                                        containerColor = MaterialTheme.colorScheme.errorContainer
                                    ),
                                    modifier = Modifier
                                        .weight(1f)
                                        .fillMaxWidth()
                                        .padding(vertical = 16.dp)
                                ) {
                                    Column(
                                        modifier = Modifier
                                            .fillMaxSize()
                                            .padding(24.dp),
                                        verticalArrangement = Arrangement.Center,
                                        horizontalAlignment = Alignment.CenterHorizontally
                                    ) {
                                        Icon(
                                            imageVector = Icons.Default.ErrorOutline,
                                            contentDescription = null,
                                            modifier = Modifier.size(48.dp),
                                            tint = MaterialTheme.colorScheme.onErrorContainer
                                        )
                                        Spacer(modifier = Modifier.height(16.dp))
                                        Text(
                                            text = "Static Extraction Error",
                                            fontWeight = FontWeight.Bold,
                                            style = MaterialTheme.typography.titleMedium,
                                            color = MaterialTheme.colorScheme.onErrorContainer
                                        )
                                        Spacer(modifier = Modifier.height(8.dp))
                                        Text(
                                            text = state.exceptionMessage,
                                            textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                                            color = MaterialTheme.colorScheme.onErrorContainer,
                                            fontSize = 14.sp
                                        )
                                        Spacer(modifier = Modifier.height(24.dp))
                                        Button(
                                            colors = ButtonDefaults.buttonColors(
                                                containerColor = MaterialTheme.colorScheme.error
                                            ),
                                            onClick = { viewModel.resetToIdle() }
                                        ) {
                                            Text("Try Again")
                                        }
                                    }
                                }
                            }
                            is AnalysisUiState.Success -> {
                                ReportDetailView(
                                    viewModel = viewModel,
                                    report = state.report,
                                    modifier = Modifier.weight(1f),
                                    onViewSmali = { finding ->
                                        viewModel.setViewingFinding(finding)
                                    }
                                )
                            }
                        }
                    }
                }
                1 -> {
                    // Decompilation & indexing history listing
                    Column(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(16.dp)
                    ) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(bottom = 12.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                text = "فهرس قاعدة بيانات التحليل",
                                style = MaterialTheme.typography.titleMedium,
                                fontWeight = FontWeight.Bold
                            )
                            if (savedReports.isNotEmpty()) {
                                TextButton(
                                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error),
                                    onClick = { viewModel.clearAllReports() }
                                ) {
                                    Icon(Icons.Default.DeleteSweep, contentDescription = null)
                                    Spacer(modifier = Modifier.width(4.dp))
                                    Text("مسح فهرس البيانات")
                                }
                            }
                        }

                        if (savedReports.isEmpty()) {
                            Box(
                                modifier = Modifier
                                    .weight(1f)
                                    .fillMaxWidth(),
                                contentAlignment = Alignment.Center
                            ) {
                                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                                    Icon(
                                        imageVector = Icons.Default.LayersClear,
                                        contentDescription = null,
                                        modifier = Modifier.size(48.dp),
                                        tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                                    )
                                    Spacer(modifier = Modifier.height(8.dp))
                                    Text("لا توجد تقارير محفوظة", fontWeight = FontWeight.SemiBold)
                                    Text(
                                        text = "يتم فهرسة التقارير التي تمت معالجتها هنا تلقائيًا.",
                                        fontSize = 12.sp,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant
                                    )
                                }
                            }
                        } else {
                            LazyColumn(
                                modifier = Modifier.weight(1f),
                                verticalArrangement = Arrangement.spacedBy(8.dp)
                            ) {
                                items(savedReports) { report ->
                                    SavedReportItem(
                                        report = report,
                                        onSelect = {
                                            viewModel.loadSavedReport(report)
                                            activeTab = 0
                                        },
                                        onDelete = {
                                            viewModel.deleteReport(report.id)
                                        }
                                    )
                                }
                            }
                        }
                    }
                }
                2 -> {
                    val settings by viewModel.settings.collectAsState()
                    SettingsScreen(settings = settings, onSettingsChange = { viewModel.updateSettings(it) })
                }
            }

            // Interactive Smali Code Viewer Modal Overlay
            viewingFinding?.let { finding ->
                SmaliViewerOverlay(
                    finding = finding,
                    onDismiss = { viewModel.setViewingFinding(null) }
                )
            }
        }
    }
}

@Composable
fun ReportDetailView(
    viewModel: AnalyzerViewModel,
    report: ApkAnalysisReport,
    modifier: Modifier = Modifier,
    onViewSmali: (AnalysisFinding) -> Unit
) {
    val searchQuery by viewModel.searchQuery.collectAsState()
    val filterType by viewModel.filterType.collectAsState()
    val filteredFindings by viewModel.filteredFindings.collectAsState()
    var expandedFindings by remember { mutableStateOf(setOf<AnalysisFinding>()) }
    
    LazyColumn(modifier = modifier) {
        item {
            // Report basic parameters
            Card(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 12.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceColorAtElevation(1.dp)
                )
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = report.fileName,
                            fontWeight = FontWeight.Bold,
                            style = MaterialTheme.typography.titleMedium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f)
                        )
                        Text(
                            text = formatFileSize(report.fileSize),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    Spacer(modifier = Modifier.height(4.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        LabelValueChip(label = "DEX Files", value = "${report.totalDexCount}")
                        LabelValueChip(label = "Classes", value = "${report.totalClassesCount}")
                        LabelValueChip(label = "Methods", value = "${report.totalMethodsCount}")
                    }

                    // Billing SDK detected tags block
                    if (report.billingSdkDetected.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = "Detected Vendor Billing SDKs:",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.primary,
                            fontWeight = FontWeight.SemiBold
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(6.dp)
                        ) {
                            report.billingSdkDetected.forEach { sdk ->
                                Box(
                                    modifier = Modifier
                                        .clip(RoundedCornerShape(4.dp))
                                        .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.2f))
                                        .padding(horizontal = 6.dp, vertical = 2.dp)
                                ) {
                                    Text(
                                        text = sdk,
                                        fontSize = 10.sp,
                                        fontWeight = FontWeight.Bold,
                                        color = MaterialTheme.colorScheme.primary
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
        
        item {
            // Filter chips bar
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { viewModel.updateSearchQuery(it) },
                    placeholder = { Text("Filter classes, methods or signatures...", fontSize = 12.sp) },
                    modifier = Modifier
                        .weight(1f)
                        .height(48.dp),
                    textStyle = LocalTextStyle.current.copy(fontSize = 12.sp),
                    singleLine = true,
                    leadingIcon = { Icon(Icons.Default.Search, contentDescription = null, modifier = Modifier.size(16.dp)) },
                    trailingIcon = if (searchQuery.isNotEmpty()) {
                        { 
                            IconButton(onClick = { viewModel.updateSearchQuery("") }) {
                                Icon(Icons.Default.Close, contentDescription = "Clear search", modifier = Modifier.size(16.dp))
                            }
                        }
                    } else null
                )

                // Category filters
                Box {
                    var expandedFilters by remember { mutableStateOf(false) }
                    Button(
                        onClick = { expandedFilters = true },
                        modifier = Modifier.height(48.dp),
                        shape = RoundedCornerShape(8.dp)
                    ) {
                        Icon(Icons.Default.FilterList, contentDescription = null, modifier = Modifier.size(16.dp))
                        Spacer(modifier = Modifier.width(4.dp))
                        Text(
                            text = when (filterType) {
                                FindingType.BILLING_SDK -> "Billing"
                                FindingType.CRITICAL_METHOD -> "Method Gates"
                                FindingType.HEURISTIC -> "Heuristic"
                                FindingType.NETWORK_VERIFICATION -> "Network"
                                null -> "All Signatures"
                            },
                            fontSize = 12.sp
                        )
                    }
                    DropdownMenu(
                        expanded = expandedFilters,
                        onDismissRequest = { expandedFilters = false }
                    ) {
                        DropdownMenuItem(
                            text = { Text("All Signatures") },
                            onClick = { viewModel.updateFilterType(null); expandedFilters = false }
                        )
                        DropdownMenuItem(
                            text = { Text("Google Play Billing Api") },
                            onClick = { viewModel.updateFilterType(FindingType.BILLING_SDK); expandedFilters = false }
                        )
                        DropdownMenuItem(
                            text = { Text("Signature/Pkg Verifiers") },
                            onClick = { viewModel.updateFilterType(FindingType.NETWORK_VERIFICATION); expandedFilters = false }
                        )
                        DropdownMenuItem(
                            text = { Text("Decision Loops / Boolean Gates") },
                            onClick = { viewModel.updateFilterType(FindingType.CRITICAL_METHOD); expandedFilters = false }
                        )
                        DropdownMenuItem(
                            text = { Text("Heuristic License Flags") },
                            onClick = { viewModel.updateFilterType(FindingType.HEURISTIC); expandedFilters = false }
                        )
                    }
                }
            }
        }
        
        item {
            val clipboardManager = LocalClipboardManager.current
            Button(
                onClick = {
                    val allText = filteredFindings.mapIndexed { index, it ->
                        """
                        [${index + 1}]
                        Category: ${it.category}
                        Class: ${it.className}
                        Method: ${it.methodName}
                        Package: ${it.packageName}
                        File: ${it.dexFileName}
                        Reason: ${it.reason}
                        Explanation: ${it.detailedExplanation}
                        Confidence: ${it.confidence}%
                        Pattern: ${it.triggerPattern}
                        Strings: ${it.referencedStrings.joinToString(", ")}
                        -------------------------------------------
                        """.trimIndent()
                    }.joinToString("\n\n")
                    clipboardManager.setText(AnnotatedString(allText))
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.secondary)
            ) {
                Icon(Icons.Default.ContentCopy, contentDescription = null, modifier = Modifier.size(18.dp))
                Spacer(modifier = Modifier.width(8.dp))
                Text("نسخ كل النتائج")
            }
        }

        // Execution Flow Section
        if (report.executionFlows.isNotEmpty()) {
            item {
                Text(
                    text = "EXECUTION PATH MAPS (HEURISTIC FLOWS):",
                    style = MaterialTheme.typography.labelSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(vertical = 4.dp)
                )

                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.tertiaryContainer.copy(alpha = 0.2f)
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 12.dp)
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        report.executionFlows.forEach { flow ->
                            Column(modifier = Modifier.padding(vertical = 4.dp)) {
                                Row(verticalAlignment = Alignment.CenterVertically) {
                                    Icon(Icons.Default.DoubleArrow, contentDescription = null, modifier = Modifier.size(14.dp), tint = MaterialTheme.colorScheme.primary)
                                    Spacer(modifier = Modifier.width(6.dp))
                                    Text(
                                        text = "Trigger Method: ${flow.triggerFinding.methodName}",
                                        fontWeight = FontWeight.Bold,
                                        fontSize = 11.sp,
                                        color = MaterialTheme.colorScheme.primary
                                    )
                                }
                                Spacer(modifier = Modifier.height(4.dp))
                                flow.path.forEachIndexed { idx, step ->
                                    Row(
                                        modifier = Modifier.padding(start = 16.dp),
                                        verticalAlignment = Alignment.CenterVertically
                                    ) {
                                        Text(
                                            text = "[Step ${idx + 1}] ${step.className.substringAfterLast("/")} -> ${step.methodName}",
                                            fontSize = 10.sp,
                                            fontFamily = FontFamily.Monospace,
                                            color = MaterialTheme.colorScheme.onSurface
                                        )
                                        Spacer(modifier = Modifier.width(4.dp))
                                        Text(
                                            text = "(${step.arrowText})",
                                            fontSize = 9.sp,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant
                                        )
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        item {
            Text(
                text = "SCAN FINDINGS & DETECTED CLASS DEFS (${filteredFindings.size}):",
                style = MaterialTheme.typography.labelSmall,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.secondary,
                modifier = Modifier.padding(vertical = 4.dp)
            )
        }

        if (filteredFindings.isEmpty()) {
            item {
                Box(
                    modifier = Modifier
                        .fillParentMaxHeight(0.3f)
                        .fillMaxWidth(),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "No heuristic signatures matched search criteria.",
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        } else {
            items(filteredFindings, key = { it.className + it.methodName }) { finding ->
                FindingItemCard(
                    finding = finding,
                    isExpanded = expandedFindings.contains(finding),
                    onToggleExpand = {
                        expandedFindings = if (expandedFindings.contains(finding)) {
                            expandedFindings - finding
                        } else {
                            expandedFindings + finding
                        }
                    },
                    onViewSmali = { onViewSmali(finding) }
                )
            }
        }
    }
}

@Composable
fun FindingItemCard(
    finding: AnalysisFinding,
    isExpanded: Boolean,
    onToggleExpand: () -> Unit,
    onViewSmali: () -> Unit
) {
    var showDialog by remember { mutableStateOf(false) }

    if (showDialog) {
        AlertDialog(
            onDismissRequest = { showDialog = false },
            title = { Text("شرح المنطق المكتشف") },
            text = { Text(finding.detailedExplanation) },
            confirmButton = {
                TextButton(onClick = { showDialog = false }) { Text("إغلاق") }
            }
        )
    }

    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onToggleExpand() },
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceColorAtElevation(if (isExpanded) 3.dp else 1.dp)
        )
    ) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.Top
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            modifier = Modifier
                                .clip(RoundedCornerShape(4.dp))
                                .background(
                                    when (finding.type) {
                                        FindingType.BILLING_SDK -> Color(0xFFD32F2F)
                                        FindingType.CRITICAL_METHOD -> Color(0xFFF57C00)
                                        FindingType.HEURISTIC -> Color(0xFF1976D2)
                                        FindingType.NETWORK_VERIFICATION -> Color(0xFF388E3C)
                                    }
                                )
                                .padding(horizontal = 6.dp, vertical = 2.dp)
                        ) {
                            Text(
                                text = finding.category.uppercase(),
                                color = Color.White,
                                fontSize = 9.sp,
                                fontWeight = FontWeight.Bold
                            )
                        }
                        if (finding.confidence >= 90) {
                            Spacer(modifier = Modifier.width(6.dp))
                            Box(
                                modifier = Modifier
                                    .clip(RoundedCornerShape(4.dp))
                                    .background(Color(0xFFFFC107))
                                    .padding(horizontal = 6.dp, vertical = 2.dp)
                            ) {
                                Text(
                                    text = "HIGH RISK",
                                    color = Color.Black,
                                    fontSize = 9.sp,
                                    fontWeight = FontWeight.Bold
                                )
                            }
                        }
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(
                            text = "Confidence: ${finding.confidence}%",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = if (finding.confidence >= 80) Color(0xFFD32F2F) else MaterialTheme.colorScheme.primary
                        )
                    }
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = finding.className.substringAfterLast("/"),
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                    Text(
                        text = "Method: ${finding.methodName}",
                        fontFamily = FontFamily.Monospace,
                        fontSize = 12.sp,
                        color = MaterialTheme.colorScheme.primary
                    )
                }

                Row {
                    IconButton(onClick = { showDialog = true }) {
                        Icon(
                            imageVector = Icons.Default.Info,
                            contentDescription = "شرح",
                            tint = MaterialTheme.colorScheme.secondary
                        )
                    }
                    IconButton(onClick = onViewSmali) {
                        Icon(
                            imageVector = Icons.Default.Code,
                            contentDescription = "View Smali Bytecode",
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                    Icon(
                        imageVector = if (isExpanded) Icons.Default.KeyboardArrowUp else Icons.Default.KeyboardArrowDown,
                        contentDescription = null,
                        modifier = Modifier.padding(top = 12.dp)
                    )
                }
            }

            if (isExpanded) {
                Spacer(modifier = Modifier.height(4.dp))
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.5f))
                Spacer(modifier = Modifier.height(8.dp))
                
                val clipboardManager = LocalClipboardManager.current
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    OutlinedButton(onClick = { clipboardManager.setText(AnnotatedString(finding.className)) }, modifier = Modifier.weight(1f)) {
                        Text("نسخ الكلاس", fontSize = 10.sp)
                    }
                    OutlinedButton(onClick = { clipboardManager.setText(AnnotatedString(finding.methodName)) }, modifier = Modifier.weight(1f)) {
                        Text("نسخ الدالة", fontSize = 10.sp)
                    }
                    Button(onClick = { /* TODO implement patching */ }, modifier = Modifier.weight(1f), colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.tertiary)) {
                        Text("باتش (تجريبي)", fontSize = 10.sp)
                    }
                }
                Spacer(modifier = Modifier.height(8.dp))
                
                Text(
                    text = finding.reason,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                
                Spacer(modifier = Modifier.height(6.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Text(
                        text = "Source: ${finding.dexFileName}",
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "Package: ${finding.packageName}",
                        fontSize = 10.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }
    }
}

@Composable
fun SavedReportItem(
    report: SavedReport,
    onSelect: () -> Unit,
    onDelete: () -> Unit
) {
    val sdf = remember { SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()) }
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .clickable { onSelect() },
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceColorAtElevation(1.dp)
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = report.fileName,
                    fontWeight = FontWeight.Bold,
                    fontSize = 14.sp,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = formatFileSize(report.fileSize),
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "• ${report.totalDexCount} DEX files",
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Text(
                        text = "• ${report.findings.size} findings",
                        fontSize = 11.sp,
                        color = MaterialTheme.colorScheme.secondary,
                        fontWeight = FontWeight.SemiBold
                    )
                }
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = "Scanned on ${sdf.format(Date(report.timestamp))}",
                    fontSize = 10.sp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            IconButton(onClick = onDelete) {
                Icon(
                    imageVector = Icons.Default.Delete,
                    contentDescription = "Remove report index",
                    tint = MaterialTheme.colorScheme.error
                )
            }
        }
    }
}

@Composable
fun LabelValueChip(label: String, value: String) {
    Box(
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .padding(horizontal = 8.dp, vertical = 4.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = "$label: ",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Text(
                text = value,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.primary
            )
        }
    }
}

@Composable
fun SettingsScreen(settings: AnalysisSettings, onSettingsChange: (AnalysisSettings) -> Unit) {
    Column(modifier = Modifier.padding(16.dp)) {
        Text("الإعدادات", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)
        Spacer(modifier = Modifier.height(16.dp))
        
        // Language
        Text("اللغة", style = MaterialTheme.typography.titleMedium)
        Spacer(modifier = Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            val isEnglish = settings.languageCode == "en"
            OutlinedButton(
                onClick = { onSettingsChange(settings.copy(languageCode = "ar")) },
                border = if (!isEnglish) BorderStroke(2.dp, MaterialTheme.colorScheme.primary) else null
            ) {
                Text("العربية")
            }
            OutlinedButton(
                onClick = { onSettingsChange(settings.copy(languageCode = "en")) },
                border = if (isEnglish) BorderStroke(2.dp, MaterialTheme.colorScheme.primary) else null
            ) {
                Text("English")
            }
        }
        
        Spacer(modifier = Modifier.height(16.dp))
        
        // Analysis Toggles
        Text("إعدادات التحليل", style = MaterialTheme.typography.titleMedium)
        
        SettingToggle("فحص دوالي الشراء", settings.scanBillingSdk) { onSettingsChange(settings.copy(scanBillingSdk = it)) }
        SettingToggle("فحص الدوال الحرجة", settings.scanCriticalMethods) { onSettingsChange(settings.copy(scanCriticalMethods = it)) }
        SettingToggle("فحص الأنماط الاستدلالية", settings.scanHeuristicPatterns) { onSettingsChange(settings.copy(scanHeuristicPatterns = it)) }
        SettingToggle("فحص اتصالات الشبكة", settings.scanNetworkVerification) { onSettingsChange(settings.copy(scanNetworkVerification = it)) }
    }
}

@Composable
fun SettingToggle(label: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label)
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}

@Composable
fun SmaliViewerOverlay(
    finding: AnalysisFinding,
    onDismiss: () -> Unit
) {
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(Color.Black.copy(alpha = 0.6f))
            .clickable { onDismiss() },
        contentAlignment = Alignment.Center
    ) {
        Card(
            modifier = Modifier
                .fillMaxWidth(0.95f)
                .fillMaxHeight(0.85f)
                .clickable(enabled = false) { }, // Prevent bubble dismissal click
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surface
            )
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp)
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = "معاينة شيفرة Smali و Opcodes",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            text = "${finding.className.substringAfterLast("/")} -> ${finding.methodName}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Default.Close, contentDescription = "Close overlay")
                    }
                }

                HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp))

                // Metadata cards
                Card(
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.3f)
                    ),
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(bottom = 12.dp)
                ) {
                    Column(modifier = Modifier.padding(10.dp)) {
                        Text(
                            text = "Trigger Condition: ${finding.triggerPattern}",
                            fontSize = 11.sp,
                            fontWeight = FontWeight.Bold,
                            color = MaterialTheme.colorScheme.secondary
                        )
                        if (finding.referencedStrings.isNotEmpty()) {
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = "Const Strings: ${finding.referencedStrings.joinToString()}",
                                fontSize = 10.sp,
                                fontFamily = FontFamily.Monospace,
                                color = MaterialTheme.colorScheme.onSurface
                            )
                        }
                    }
                }

                Text(
                    text = "Disassembled Bytecode Representation:",
                    fontSize = 11.sp,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(bottom = 6.dp)
                )

                // Scrollable smali text block
                Box(
                    modifier = Modifier
                        .weight(1f)
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(4.dp))
                        .background(Color(0xFF1E1E1E))
                        .padding(10.dp)
                ) {
                    LazyColumn(modifier = Modifier.fillMaxSize()) {
                        item {
                            Text(
                                text = finding.smaliSnippet,
                                color = Color(0xFFA9B7C6),
                                fontFamily = FontFamily.Monospace,
                                fontSize = 11.sp,
                                lineHeight = 14.sp
                            )
                        }
                    }
                }
            }
        }
    }
}

fun formatFileSize(bytes: Long): String {
    if (bytes <= 0) return "0 B"
    val units = arrayOf("B", "KB", "MB", "GB", "TB")
    val digitGroups = (Math.log10(bytes.toDouble()) / Math.log10(1024.0)).toInt()
    return DecimalFormat("#,##0.#").format(bytes / Math.pow(1024.0, digitGroups.toDouble())) + " " + units[digitGroups]
}
