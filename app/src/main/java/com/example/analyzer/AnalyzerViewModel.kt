package com.example.analyzer

import android.app.Application
import android.content.Context
import android.net.Uri
import androidx.lifecycle.*
import androidx.room.Room
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

sealed interface AnalysisUiState {
    object Idle : AnalysisUiState
    data class Loading(val message: String) : AnalysisUiState
    data class Success(val report: ApkAnalysisReport) : AnalysisUiState
    data class Error(val exceptionMessage: String) : AnalysisUiState
}

class AnalyzerViewModel(application: Application) : AndroidViewModel(application) {

    private val db = Room.databaseBuilder(
        application.applicationContext,
        AnalyzerDatabase::class.java,
        "apk_dex_analyzer_db"
    ).fallbackToDestructiveMigration().build()

    private val savedReportDao = db.savedReportDao()
    private val engine = AnalyzerEngine(application.applicationContext)

    private val _settings = MutableStateFlow(AnalysisSettings())
    val settings: StateFlow<AnalysisSettings> = _settings.asStateFlow()

    fun updateSettings(newSettings: AnalysisSettings) {
        _settings.value = newSettings
    }

    private val _uiState = MutableStateFlow<AnalysisUiState>(AnalysisUiState.Idle)
    val uiState: StateFlow<AnalysisUiState> = _uiState.asStateFlow()

    // Search and Filter State
    private val _searchQuery = MutableStateFlow("")
    val searchQuery: StateFlow<String> = _searchQuery.asStateFlow()

    private val _filterType = MutableStateFlow<FindingType?>(null)
    val filterType: StateFlow<FindingType?> = _filterType.asStateFlow()

    val filteredFindings: StateFlow<List<AnalysisFinding>> = combine(
        uiState.map { (it as? AnalysisUiState.Success)?.report?.findings ?: emptyList() },
        _searchQuery,
        _filterType
    ) { findings, query, filter ->
        findings.filter { finding ->
            (filter == null || finding.type == filter) &&
                    (query.isEmpty() ||
                            finding.className.contains(query, ignoreCase = true) ||
                            finding.methodName.contains(query, ignoreCase = true) ||
                            finding.category.contains(query, ignoreCase = true))
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(5000), emptyList())

    fun updateSearchQuery(query: String) {
        _searchQuery.value = query
    }

    fun updateFilterType(type: FindingType?) {
        _filterType.value = type
    }

    private val _statusText = MutableStateFlow<String>("")
    val statusText: StateFlow<String> = _statusText.asStateFlow()

    val savedReports: LiveData<List<SavedReport>> = savedReportDao.getAllReports().asLiveData()

    // Loaded code state parameters for Smali and Opcode Navigation viewers
    private val _viewingFinding = MutableStateFlow<AnalysisFinding?>(null)
    val viewingFinding: StateFlow<AnalysisFinding?> = _viewingFinding.asStateFlow()

    fun setViewingFinding(finding: AnalysisFinding?) {
        _viewingFinding.value = finding
    }

    fun analyzeFile(uri: Uri) {
        viewModelScope.launch {
            _uiState.value = AnalysisUiState.Loading("Initializing local workspace...")
            _statusText.value = "Scanning classes.dex structure..."
            try {
                val report = engine.analyzeApkOrDexUri(uri, _settings.value)
                _statusText.value = "Saving analysis report to index store..."

                // Save report data
                val saved = SavedReport(
                    fileName = report.fileName,
                    fileSize = report.fileSize,
                    totalDexCount = report.totalDexCount,
                    totalClassesCount = report.totalClassesCount,
                    totalMethodsCount = report.totalMethodsCount,
                    billingSdkDetected = report.billingSdkDetected,
                    findings = report.findings,
                    executionFlows = report.executionFlows,
                    timestamp = report.timestamp
                )
                savedReportDao.insertReport(saved)

                _uiState.value = AnalysisUiState.Success(report)
            } catch (e: Exception) {
                _uiState.value = AnalysisUiState.Error(e.message ?: "Unknown parser error occurred")
            }
        }
    }

    fun deleteReport(id: Int) {
        viewModelScope.launch {
            savedReportDao.deleteReportById(id)
        }
    }

    fun clearAllReports() {
        viewModelScope.launch {
            savedReportDao.deleteAllReports()
        }
    }

    fun loadSavedReport(saved: SavedReport) {
        val report = ApkAnalysisReport(
            fileName = saved.fileName,
            fileSize = saved.fileSize,
            totalDexCount = saved.totalDexCount,
            totalClassesCount = saved.totalClassesCount,
            totalMethodsCount = saved.totalMethodsCount,
            billingSdkDetected = saved.billingSdkDetected,
            findings = saved.findings,
            executionFlows = saved.executionFlows,
            timestamp = saved.timestamp
        )
        _uiState.value = AnalysisUiState.Success(report)
    }

    fun resetToIdle() {
        _uiState.value = AnalysisUiState.Idle
    }
}
