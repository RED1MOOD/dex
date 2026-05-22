package com.example.analyzer

import android.content.Context
import android.net.Uri
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.io.InputStream
import java.io.BufferedInputStream
import java.util.zip.ZipInputStream

/**
 * Intelligent Core static Analysis and Heuristics engine to find purchase, billing,
 * subscription logic, and custom feature gates.
 */
class AnalyzerEngine(private val context: Context) {

    private val dexParser = HighPerformanceDexParser()

    suspend fun analyzeApkOrDexUri(uri: Uri, settings: AnalysisSettings): ApkAnalysisReport = withContext(Dispatchers.IO) {
        val contentResolver = context.contentResolver
        val fileInputStream = contentResolver.openInputStream(uri) ?: throw Exception("Failed to open source stream")

        val totalSize = try {
            val pfd = contentResolver.openFileDescriptor(uri, "r")
            val size = pfd?.statSize ?: 0L
            pfd?.close()
            size
        } catch (e: Exception) {
            0L
        }

        var fileName = "unknown"
        contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val nameIdx = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (nameIdx != -1 && cursor.moveToFirst()) {
                fileName = cursor.getString(nameIdx)
            }
        }

        return@withContext analyzeInputStream(fileInputStream, fileName, totalSize, settings)
    }

    suspend fun analyzeInputStream(inputStream: InputStream, name: String, totalSize: Long, settings: AnalysisSettings): ApkAnalysisReport = withContext(Dispatchers.IO) {
        val bufferedInput = BufferedInputStream(inputStream)

        val tempFile = File.createTempFile("analysis_temp_", ".bin", context.cacheDir)
        try {
            tempFile.outputStream().use { fos ->
                bufferedInput.copyTo(fos)
            }
        } catch (e: Exception) {
            // failover
            tempFile.delete()
            throw e
        }

        val billingSdks = mutableSetOf<String>()
        val classDefs = mutableListOf<ClassDefInfo>()
        var totalDexFilesCount = 0
        var totalMethodsCount = 0

        // Parse temporary zip file or binary dex straight away
        try {
            // First treat as Zip (APK payload container)
            var dexParsedCount = 0
            tempFile.inputStream().use { fileIn ->
                ZipInputStream(BufferedInputStream(fileIn)).use { zipIn ->
                    var entry = zipIn.getNextEntry()
                    while (entry != null) {
                        if (entry.name.endsWith(".dex")) {
                            totalDexFilesCount++
                            // Parse individual Dex contents asynchronously
                            val (dexClasses, methodCount) = dexParser.parseDexData(zipIn, entry.name)
                            classDefs.addAll(dexClasses)
                            totalMethodsCount += methodCount
                            dexParsedCount++
                        }
                        entry = zipIn.getNextEntry()
                    }
                }
            }

            // If no DEX entries parsed, treat file as a clean direct binary classes.dex itself!
            if (dexParsedCount == 0) {
                tempFile.inputStream().use { directIn ->
                    val (dexClasses, methodCount) = dexParser.parseDexData(directIn, name)
                    if (dexClasses.isNotEmpty()) {
                        classDefs.addAll(dexClasses)
                        totalMethodsCount += methodCount
                        totalDexFilesCount = 1
                    }
                }
            }

        } finally {
            try {
                tempFile.delete()
            } catch (e: Exception) {
                // silented deletion failures
            }
        }

        // Conduct intensive code level analysis utilizing static heuristics engine
        val findings = runHeuristicScanners(classDefs, billingSdks, settings)
        val executionFlows = buildExecutionFlows(classDefs, findings)

        return@withContext ApkAnalysisReport(
            fileName = name,
            fileSize = totalSize,
            totalDexCount = totalDexFilesCount,
            totalClassesCount = classDefs.size,
            totalMethodsCount = totalMethodsCount,
            billingSdkDetected = billingSdks.toList(),
            findings = findings,
            executionFlows = executionFlows
        )
    }

    private fun runHeuristicScanners(
        classes: List<ClassDefInfo>,
        billingSdks: MutableSet<String>,
        settings: AnalysisSettings
    ): List<AnalysisFinding> {
        val findings = ArrayList<AnalysisFinding>()

        // Specific billing and verify signatures
        val billingSignatures = mapOf(
            "com/android/billingclient" to "Google Play Billing SDK",
            "com/revenuecat/purchases" to "RevenueCat Subscription SDK",
            "com/stripe/android" to "Stripe Payment SDK",
            "com/huawei/hms/iap" to "Huawei In-App Billing SDK",
            "com/samsung/android/iap" to "Samsung IAP SDK",
            "com/paypal/android" to "PayPal SDK",
            "com/braintreepayments" to "Braintree SDK"
        )

        val criticalKeywords = setOf(
            "purchase", "buy", "launchbillingflow", "verify", "validate",
            "acknowledgepurchase", "subscription", "entitlement", "ispremium",
            "unlockpro", "unlockpremium", "hasvip", "checklicense", "isvip",
            "checkpremium", "getsku", "checksubscription", "activatesubscription",
            "onbillinginitialized", "billingclient", "getpurchases"
        )

        for (clazz in classes) {
            val classNameLower = clazz.className.lowercase()

            // 1. Scan SDK packages
            for ((sig, sdkName) in billingSignatures) {
                if (clazz.className.contains(sig)) {
                    billingSdks.add(sdkName)
                }
            }

            for ((methodName, method) in clazz.methods) {
                val methodNameLower = methodName.lowercase()

                // Rule-based heuristic verification for purchase, locks and signatures
                var isMatched = false
                var matchCategory = ""
                var confidence = 0
                var reason = ""
                var triggerPattern = ""

                // Enhanced Pattern: Look for combination of Premium/License keywords AND control flow
                val premiumKeywords = setOf(
                    "premium", "pro", "vip", "subscription", "purchase", "paid", "unlock", "adfree", "license",
                    "member", "subscriber", "gold", "platinum", "diamond", "trial", "active", "ispremium", 
                    "ispro", "isvip", "hasaccess", "purchased", "is_premium", "is_pro", "is_vip", "has_access"
                )
                
                val hasPremiumKeyword = method.referencedStrings.any { str ->
                    val lower = str.lowercase()
                    premiumKeywords.any { kw -> lower.contains(kw) }
                }
                
                // Server-side detection heuristic
                val networkKeywords = setOf(
                    "okhttp", "retrofit", "httpurlconnection", "volley", "api", "url", "json", "connection", 
                    "server", "request", "response", "cloud"
                )
                val isServerSide = method.calledMethodsSignatures.any { sig ->
                    val lower = sig.lowercase()
                    networkKeywords.any { kw -> lower.contains(kw) }
                }

                val hasControlFlow = method.rawOpcodes.any { it.opcodeName.startsWith("if-") }

                if (methodNameLower.contains("launchbillingflow") || methodNameLower.contains("purchase")) {
                    matchCategory = "Purchase Launch Logic"
                    reason = "Critical billing flow initiation." + if (isServerSide) " [SERVER-SIDE]" else ""
                    confidence = 90
                    triggerPattern = "method: $methodName"
                    isMatched = true
                } else if (methodNameLower.contains("verify") || methodNameLower.contains("validate")) {
                    matchCategory = "Receipt Verification"
                    reason = "Serious validation logic." + if (isServerSide) " [SERVER-SIDE]" else ""
                    confidence = 95
                    triggerPattern = "method: $methodName"
                    isMatched = true
                } else if (hasPremiumKeyword && hasControlFlow) {
                    matchCategory = "Feature Entitlement Gate"
                    reason = "Strong evidence of a security gate: premium logic combined with branching control flow." + if (isServerSide) " [SERVER-SIDE]" else ""
                    confidence = 98
                    triggerPattern = "Method: $methodName (Control Flow + Premium/Subscription Sig)"
                    isMatched = true
                } else if (methodNameLower.contains("ispremium") || methodNameLower.contains("is_premium") || 
                           methodNameLower.contains("unlockpro") || methodNameLower.contains("ispro") || 
                           methodNameLower.contains("is_pro") || methodNameLower.contains("hasvip") || 
                           methodNameLower.contains("isvip") || methodNameLower.contains("is_vip") || 
                           methodNameLower.contains("issubscribed") || methodNameLower.contains("is_subscribed")) {
                    matchCategory = "Feature Entitlement Gate"
                    reason = "Direct entitlement check gate found (premium/subscription status)." + if (isServerSide) " [SERVER-SIDE]" else ""
                    confidence = 98
                    triggerPattern = "method: $methodName"
                    isMatched = true
                }

                if (isMatched && confidence >= 80) {
                    // Filter based on settings (keep existing filter logic)
                    val shouldAdd = when (matchCategory) {
                        "Purchase Launch Logic", "Receipt Verification" -> settings.scanBillingSdk
                        "Feature Entitlement Gate" -> settings.scanCriticalMethods
                        "Local Heuristic Pattern Match" -> settings.scanHeuristicPatterns
                        "Network License Check" -> settings.scanNetworkVerification
                        else -> true
                    }

                    if (shouldAdd) {
                        findings.add(
                            AnalysisFinding(
                                type = when (matchCategory) {
                                    "Purchase Launch Logic", "Receipt Verification" -> FindingType.BILLING_SDK
                                    "Local Heuristic Pattern Match" -> FindingType.HEURISTIC
                                    "Network License Check" -> FindingType.NETWORK_VERIFICATION
                                    else -> FindingType.CRITICAL_METHOD
                                },
                                category = matchCategory,
                                className = clazz.className,
                                methodName = methodName,
                                packageName = parsePackageFromClassName(clazz.className),
                                dexFileName = clazz.dexFileName,
                                reason = reason,
                                detailedExplanation = generateExplanation(matchCategory, reason),
                                confidence = confidence,
                                triggerPattern = triggerPattern,
                                smaliSnippet = generateDisassembledSmaliPreview(method),
                                referencedStrings = method.referencedStrings
                            )
                        )
                    }
                }
            }
        }

        return findings.sortedByDescending { it.confidence }
    }

    private fun generateExplanation(category: String, reason: String): String {
        return when (category) {
            "Purchase Launch Logic" -> "هذه الدالة مسؤولة عن بدء عملية الشراء مباشرة. قد يتم التلاعب بها لتجاوز المدفوعات."
            "Receipt Verification" -> "هذه الدالة تتحقق من صحة إيصال الشراء. المسيرات في هذا النوع غالباً ما تكون مستهدفة لعمليات التزييف."
            "Feature Entitlement Gate" -> "هذه الدالة تعمل كقفل للمميزات المدفوعة. القيمة التي ترجعها (boolean) تحدد إمكانية وصول المستخدم للمميزات."
            "Local Heuristic Pattern Match" -> "تم العثور على سلاسل نصية مريبة تشير إلى وجود فحص ترخيص محلي."
            "Network License Check" -> "هذه الدالة تقوم بإجراء فحص للترخيص عبر الشبكة."
            else -> "هذه المنطقة قد تحتوي على منطق حساس يتعلق بالأمان أو التحقق."
        }
    }

    private fun buildExecutionFlows(
        classes: List<ClassDefInfo>,
        findings: List<AnalysisFinding>
    ): List<ExecutionFlow> {
        val flows = ArrayList<ExecutionFlow>()
        // Build interactive logic call graphs
        // Focus on Purchase -> Verification -> Unlock sequence tracking
        val verifyFindings = findings.filter { it.category == "Receipt Verification" }
        val gateFindings = findings.filter { it.category == "Feature Entitlement Gate" }

        for (finding in findings) {
            if (finding.category == "Purchase Launch Logic") {
                // Find potential execution channels using trace invocations
                val flowSteps = ArrayList<FlowStep>()
                flowSteps.add(FlowStep(finding.className, finding.methodName, "initiates billing"))

                // Link to adjacent verify findings
                val adjacentVerify = verifyFindings.firstOrNull {
                    it.className == finding.className || it.packageName == finding.packageName
                }
                if (adjacentVerify != null) {
                    flowSteps.add(FlowStep(adjacentVerify.className, adjacentVerify.methodName, "validates token online"))
                }

                // Link to unlock screen/logic triggers
                val adjacentGate = gateFindings.firstOrNull {
                    it.className == finding.className || it.packageName == finding.packageName
                } ?: gateFindings.firstOrNull()

                if (adjacentGate != null) {
                    flowSteps.add(FlowStep(adjacentGate.className, adjacentGate.methodName, "unlocks UI components"))
                }

                if (flowSteps.size > 1) {
                    flows.add(
                        ExecutionFlow(
                            triggerFinding = finding,
                            path = flowSteps
                        )
                    )
                }
            }
        }
        return flows
    }

    private fun parsePackageFromClassName(className: String): String {
        // e.g., Lcom/example/billing/BillingActivity; -> com.example.billing
        val clean = className.trimStart('L').trimEnd(';')
        val idx = clean.lastIndexOf('/')
        return if (idx != -1) {
            clean.substring(0, idx).replace('/', '.')
        } else {
            "default"
        }
    }

    private fun generateDisassembledSmaliPreview(method: MethodDefInfo): String {
        val sb = java.lang.StringBuilder()
        sb.append(".method public ${method.methodName}${method.signature}\n")
        sb.append("    .registers 8\n")
        sb.append("    .locals 4\n\n")

        for (str in method.referencedStrings) {
            val safeStr = str.replace("\n", "\\n").replace("\"", "\\\"")
            sb.append("    const-string v0, \"$safeStr\"\n")
        }

        for (call in method.calledMethodsSignatures) {
            sb.append("    invoke-static {}, L$call\n")
        }

        if (method.rawOpcodes.isNotEmpty()) {
            sb.append("\n    # Opcode Instruction Sequence Mapping\n")
            for (op in method.rawOpcodes.take(15)) {
                sb.append("    ${op.opcodeName} // offset: ${op.offset}\n")
            }
            if (method.rawOpcodes.size > 15) {
                sb.append("    ... (${method.rawOpcodes.size - 15} instructions remaining)\n")
            }
        } else {
            sb.append("    return-void\n")
        }
        sb.append(".end method")
        return sb.toString()
    }
}
