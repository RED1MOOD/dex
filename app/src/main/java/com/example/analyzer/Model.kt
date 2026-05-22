package com.example.analyzer

import androidx.room.TypeConverter
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory

// Holds the high-level metadata and overall findings of an APK or DEX analysis session.
data class ApkAnalysisReport(
    val fileName: String,
    val fileSize: Long,
    val totalDexCount: Int,
    val totalClassesCount: Int,
    val totalMethodsCount: Int,
    val billingSdkDetected: List<String>,
    val findings: List<AnalysisFinding>,
    val executionFlows: List<ExecutionFlow>,
    val timestamp: Long = System.currentTimeMillis()
)

// App-wide configuration for the analyzer
data class AnalysisSettings(
    val scanBillingSdk: Boolean = true,
    val scanCriticalMethods: Boolean = true,
    val scanHeuristicPatterns: Boolean = true,
    val scanNetworkVerification: Boolean = true,
    val languageCode: String = "ar"
)

// A particular risk, security issue, billing interface, or feature gate detected.
data class AnalysisFinding(
    val type: FindingType, // BILLING_SDK, CRITICAL_METHOD, HEURISTIC, NETWORK_VERIFICATION
    val category: String,  // e.g., "Google Play Billing", "Verification Bypass", "Premium Gate"
    val className: String,
    val methodName: String,
    val packageName: String,
    val dexFileName: String,
    val reason: String,
    val detailedExplanation: String, // NEW FIELD
    val confidence: Int,   // 0 to 100 percent
    val triggerPattern: String,
    val smaliSnippet: String = "",
    val referencedStrings: List<String> = emptyList()
)

enum class FindingType {
    BILLING_SDK,
    CRITICAL_METHOD,
    HEURISTIC,
    NETWORK_VERIFICATION
}

// A full execution path displaying how billing logic connects to feature unlocking or validation.
data class ExecutionFlow(
    val triggerFinding: AnalysisFinding,
    val path: List<FlowStep>
)

data class FlowStep(
    val className: String,
    val methodName: String,
    val arrowText: String = "calls"
)

// Parsed Dex File Structures
data class DexHeader(
    val dexVersion: String,
    val stringIdsSize: Int,
    val stringIdsOff: Int,
    val typeIdsSize: Int,
    val typeIdsOff: Int,
    val protoIdsSize: Int,
    val protoIdsOff: Int,
    val methodIdsSize: Int,
    val methodIdsOff: Int,
    val classDefsSize: Int,
    val classDefsOff: Int
)

data class ClassDefInfo(
    val className: String,
    val superClassName: String?,
    val dexFileName: String,
    val classIdx: Int,
    val methods: Map<String, MethodDefInfo>
)

data class MethodDefInfo(
    val methodName: String,
    val signature: String,
    val accessFlags: Int,
    val classOwner: String,
    val dexFileName: String,
    val codeOffset: Int,
    val referencedStrings: List<String>,
    val calledMethodsIndices: List<Int>, // internal indices to project method table
    val calledMethodsSignatures: List<String>, // pre-resolved called method signatures classes
    val rawOpcodes: List<OpcodeInstruction>
)

data class OpcodeInstruction(
    val offset: Int,
    val opcodeName: String,
    val description: String
)

// Converters for Moshi serialization used by Room database
class RoomTypeConverters {
    private val moshi = Moshi.Builder().addLast(KotlinJsonAdapterFactory()).build()

    @TypeConverter
    fun stringListToJson(list: List<String>?): String {
        if (list == null) return "[]"
        val adapter = moshi.adapter<List<String>>(Types.newParameterizedType(List::class.java, String::class.java))
        return adapter.toJson(list)
    }

    @TypeConverter
    fun jsonToStringList(json: String?): List<String> {
        if (json.isNullOrEmpty()) return emptyList()
        val adapter = moshi.adapter<List<String>>(Types.newParameterizedType(List::class.java, String::class.java))
        return adapter.fromJson(json) ?: emptyList()
    }

    @TypeConverter
    fun findingsListToJson(list: List<AnalysisFinding>?): String {
        if (list == null) return "[]"
        val adapter = moshi.adapter<List<AnalysisFinding>>(Types.newParameterizedType(List::class.java, AnalysisFinding::class.java))
        return adapter.toJson(list)
    }

    @TypeConverter
    fun jsonToFindingsList(json: String?): List<AnalysisFinding> {
        if (json.isNullOrEmpty()) return emptyList()
        val adapter = moshi.adapter<List<AnalysisFinding>>(Types.newParameterizedType(List::class.java, AnalysisFinding::class.java))
        return adapter.fromJson(json) ?: emptyList()
    }

    @TypeConverter
    fun flowsListToJson(list: List<ExecutionFlow>?): String {
        if (list == null) return "[]"
        val adapter = moshi.adapter<List<ExecutionFlow>>(Types.newParameterizedType(List::class.java, ExecutionFlow::class.java))
        return adapter.toJson(list)
    }

    @TypeConverter
    fun jsonToFlowsList(json: String?): List<ExecutionFlow> {
        if (json.isNullOrEmpty()) return emptyList()
        val adapter = moshi.adapter<List<ExecutionFlow>>(Types.newParameterizedType(List::class.java, ExecutionFlow::class.java))
        return adapter.fromJson(json) ?: emptyList()
    }
}
