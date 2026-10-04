
import mongoose from "mongoose";

const FindingSchema = new mongoose.Schema({
  ruleId: { type: String, required: true },
  name: { type: String, required: true },
  status: { type: String, enum: ["PASS", "WARN", "FAIL"], required: true },
  category: { type: String, required: true },
  severity: { type: String, enum: ["LOW", "MEDIUM", "HIGH"], required: true },
  message: { type: String, required: true },
  currentValue: { type: String, default: null },
  remediation: {
    express: { type: String, default: null },
    nginx: { type: String, default: null }
  }
});

const ScanSchema = new mongoose.Schema(
  {
    testedUrl: { type: String, required: true, trim: true },
    statusCode: { type: Number, required: true },
    score: { type: Number, required: true, min: 0, max: 100 },
    grade: { type: String, required: true },
    findings: [FindingSchema]
  },
  {
    timestamps: { createdAt: "scannedAt", updatedAt: false }
  }
);

const Scan = mongoose.model("Scan", ScanSchema);

export default Scan;