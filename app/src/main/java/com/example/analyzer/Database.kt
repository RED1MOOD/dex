package com.example.analyzer

import androidx.room.*
import kotlinx.coroutines.flow.Flow

@Entity(tableName = "saved_reports")
data class SavedReport(
    @PrimaryKey(autoGenerate = true) val id: Int = 0,
    val fileName: String,
    val fileSize: Long,
    val totalDexCount: Int,
    val totalClassesCount: Int,
    val totalMethodsCount: Int,
    val billingSdkDetected: List<String>,
    val findings: List<AnalysisFinding>,
    val executionFlows: List<ExecutionFlow>,
    val timestamp: Long
)

@Dao
interface SavedReportDao {
    @Query("SELECT * FROM saved_reports ORDER BY timestamp DESC")
    fun getAllReports(): Flow<List<SavedReport>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertReport(report: SavedReport)

    @Query("DELETE FROM saved_reports WHERE id = :id")
    suspend fun deleteReportById(id: Int)

    @Query("DELETE FROM saved_reports")
    suspend fun deleteAllReports()
}

@Database(entities = [SavedReport::class], version = 2, exportSchema = false)
@TypeConverters(RoomTypeConverters::class)
abstract class AnalyzerDatabase : RoomDatabase() {
    abstract fun savedReportDao(): SavedReportDao
}
