from fastapi import FastAPI, UploadFile, File
from transformers import pipeline
import shutil
import os

app = FastAPI()

print("Loading model...")

classifier = pipeline(
    "audio-classification",
    model="MelodyMachine/Deepfake-audio-detection-V2"
)

print("Model loaded successfully.")

UPLOAD_FOLDER = "uploads"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.post("/predict")

async def predict(file: UploadFile = File(...)):

    file_path = os.path.join(
        UPLOAD_FOLDER,
        file.filename
    )

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    try:
        result = classifier(file_path)

        top = result[0]

        return {
            "filename": file.filename,
            "prediction": top["label"],
            "confidence": round(
                top["score"] * 100,
                4
            )
        }

    except Exception as e:

        return {
            "error": str(e)
        }