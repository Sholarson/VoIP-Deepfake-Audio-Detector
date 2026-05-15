import requests

# Your ngrok public URL
url = "https://slip-viable-empathy.ngrok-free.dev/predict"

# Audio file path
audio_path = "remote.wav"

try:

    with open(audio_path, "rb") as audio_file:

        files = {
            "file": audio_file
        }

        print("Sending audio for prediction...")

        response = requests.post(url, files=files)

    print("\nResponse Status:")
    print(response.status_code)

    print("\nPrediction Result:")
    print(response.json())

except Exception as e:

    print("Error:")
    print(e)
