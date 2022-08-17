//Zmniejszenie rozmiaru plików nagłówkowych Win32 poprzez wykluczenie niektórych rzadziej używanych interfejsów API
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <winsock2.h>
#include <windows.h>
#include <string.h>

//Korzystając z winsock2.h trzeba dodatkowo skorzystać z ws2_32.lib (umieszczone w CMAKE)
#pragma comment(lib, "Ws2_32.lib")

#define TEMP_SENSITIVITY 0.015625f
#define UPPER_TEMP_LIMIT 80
#define LOWER_TEMP_LIMIT -40
#define BUFLEN 128

// global running variable
_Atomic char running = 0; // default false

DWORD WINAPI sendThreadFunction(LPVOID lpParam);

/*
 * Autor: inż.Kacper Bukowski
 * Nazwa: Odczytywanie temperatury z pliku binarnego / servera TCP/IP
 * Opis: Program, który odbierze dane z urządzenia mierzącego temperaturę, przetworzy ją i wyświetli w czytelny sposób wynik na konsoli.
 * Data utworzenia: 15.08.2022
 * Argumenty wejściowe:
 * - tryb pracy (uint8_t) - 0 (odczyt z pliku binarnego), 1 (pobranie danych z servera TCP/IP)
 * DLA TRYBU 0:
 *      - ścieżka do pliku binarnego(char*)
 * DLA TRYBU 1:
 *      - adres IP
 *      - numer portu
 */

/*Definiowanie struktury przechowującej dane z ramki z atrybutem "packed" - nie będzie dodawany padding
 *z paddingiem sizeof(Frame) = 16
 *bez paddingu sizeof(Frame) = 8*/
typedef struct __attribute__((__packed__)) Frame {
    uint32_t payload;
    uint8_t N;
    uint32_t temperatureSensorID;
    int16_t digitalOutput;
    uint16_t crc16;
} Frame;
/*Definiowanie struktury przechowującej dane z ramki na potrzeby sprawdzenia sumy kontrolnej*/
typedef struct __attribute__((__packed__)) FrameCRC {
    uint32_t payload;
    uint8_t N;
    uint32_t temperatureSensorID;
    int16_t digitalOutput;
} FrameCRC;

unsigned char getCharFromBitStr(const char *BIN_STR)
{
    unsigned char temp = BIN_STR[0] - '0';

    for (int i = 1; i < 8; ++i)  // 1 byte size
        temp = (temp << 1) | (BIN_STR[i] - '0');

    return temp;
}

uint8_t saveBin(const char *FILE_NAME, const char *BIN_STR)
{
    FILE *file = fopen(FILE_NAME, "wb");

    if (file == NULL)
    {
        return 1;
    }

    const unsigned char BIN_STR_SIZE = 104;
    const char *FORMAT = "%c";

    for (int startIter = 0; startIter < BIN_STR_SIZE; startIter += 8)
        fprintf_s(file, FORMAT, getCharFromBitStr(BIN_STR + startIter));

    fclose(file);
    return 0;
}

/*Funkcja tworząca checksum CRC16-CCITT-FALSE
 *wykorzystane zostały informacje ze strony: http://srecord.sourceforge.net/crc16-ccitt.html*/

uint16_t crc16(char *pData, int length) {
    uint8_t i;
    uint16_t wCrc = 0xffff;
    while (length--) {
        wCrc ^= *(unsigned char *) pData++ << 8;
        for (i = 0; i < 8; i++)
            wCrc = wCrc & 0x8000 ? (wCrc << 1) ^ 0x1021 : wCrc << 1;
    }
    return wCrc & 0xffff;
}

/*Funkcja przygotowująca dane do testowania,
 * można wprowadzić dowolne elementy zgodnie z ramką. */

uint8_t prepareTestData(char *filePath) {
    //Utworzenie identyfikatora pliku
    FILE *inputFile;
    Frame testData = {
            .payload = 9,
            .N  = 0b00000001,
            .temperatureSensorID = 227,
            .digitalOutput = 0b01111111111111,
            .crc16 = 45904
    };
    FrameCRC checkSumCreation = {
            .payload = testData.payload,
            .N = testData.N,
            .temperatureSensorID = testData.temperatureSensorID,
            .digitalOutput = testData.digitalOutput
    };
    testData.crc16 = crc16(&checkSumCreation, sizeof(FrameCRC));

    inputFile = fopen(filePath, "wb");
    if (!inputFile) {
        return 1;
    }
    fwrite(&testData, sizeof(Frame), 1, inputFile);
    fclose(inputFile);
    return 0;
}

/*Funkcja odczytująca dane z pliku binarnego*/

uint8_t readDataFromBinary(char *filePath, Frame *inputData) {
    //Utworzenie identyfikatora pliku
    FILE *inputFile;
    //Otworzenie, odczyt, zamknięcie, sprawdzenie - taka kolejność jest bezpieczniejsza, niż sprawdzenie przed zamknięciem. Niweluje błędy
    inputFile = fopen(filePath, "rb");
    size_t sizeOfReadData = fread(inputData, sizeof(Frame), 1, inputFile);
    fclose(inputFile);
    if (sizeOfReadData == 0) {
        return 1;
    } else {
        return 0;
    }
}

/*Funkcja sprawdzająca poprawność zaczytanych danych*/

uint8_t checkDataIntegrity(Frame *inputData) {
    if (inputData->payload ==
        sizeof(inputData->N) + sizeof(inputData->temperatureSensorID) + sizeof(inputData->digitalOutput) +
        sizeof(inputData->crc16)) {
        FrameCRC checkSum = {
                .payload = inputData->payload,
                .N = inputData->N,
                .temperatureSensorID = inputData->temperatureSensorID,
                .digitalOutput = inputData->digitalOutput
        };
        if (crc16(&checkSum, sizeof(FrameCRC)) == inputData->crc16) {
            return 0;
        }
    }
    return 1;
}

/*Funkcja pobierająca LSB*/
uint8_t getLSB(uint16_t value) {
    if (value & 1) {
        return 1;
    } else {
        return 0;
    }
}

/*funkcja odczytująca 14-bitową wartość temperatury*/
float readTemperature(Frame *inputData) {
    float temp = ((int16_t) (inputData->digitalOutput << 2) / 4) * TEMP_SENSITIVITY;
    return temp;
}

/*sprawdzenie czy wartość jest w określonym przedziale*/
uint8_t checkIfInRange(float value, int8_t upperLimit, int8_t lowerLimit) {
    if (upperLimit > value && value > lowerLimit) {
        return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    //Utworzenie pustej struktury frame, która ma pełnić rolę bufora
    Frame inputData;
    uint8_t maxArgCountZero = 4;
    uint8_t maxArgCountOne = 3;
    char *filePath = NULL;

    switch (*argv[1]) {
        case '0':
            //Sprawdzenie liczby argumentów
            if (argc < maxArgCountZero && argc != 0) {
                filePath = argv[2];
                //Sprawdzenie czy plik istnieje
                if (access(filePath, F_OK) != 0) {
                    return ENOENT;
                }
            } else {
                return E2BIG;
            }
            //przygotowanie przykładowych danych (można wyłączyć) - DEV PURPOSE
            if (prepareTestData(filePath) == 1) {
                return 1;
            }
            //odczytanie danych z ramki
            if (readDataFromBinary(filePath, &inputData) == 1) {
                return 2;
            }
            //sprawdzenie danych
            if (checkDataIntegrity(&inputData) == 1) {
                return 3;
            }

            //wyświetlenie danych na konsoli
            float tempRead = readTemperature(&inputData);
            printf("Odczytana temperatura na podstawie danych z pliku to: %4.3f stC \n", tempRead);
            if (checkIfInRange(tempRead, UPPER_TEMP_LIMIT, LOWER_TEMP_LIMIT) == 1) {
                printf("WARNING! Dane z czujnika %lx(hex) wykraczaja poza zakres temperatur <%d, %d>",
                       inputData.temperatureSensorID, LOWER_TEMP_LIMIT, UPPER_TEMP_LIMIT);
            }
            return 0;
        case '1': {
            //Sprawdzenie liczby argumentów
            if (argc < maxArgCountZero && argc == 0){
                return E2BIG;
            }
            //Zmienne do klienta TCP/IP
            char *serverAddress = argv[2];
            char *port = argv[3];
            int res;
            WSADATA wsaData;
            res = WSAStartup(MAKEWORD(2, 2), &wsaData);
            if (res) {
                return ENOPROTOOPT;
            }
            //Konfiguracja socket'u
            SOCKET client;
            client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            //Sprawdzenie czy socket został poprawnie utworzony
            if (client == INVALID_SOCKET) {
                WSACleanup();
                return ENOTCONN;
            }
            //Uruchomienie połączenia do adresu:portu
            struct sockaddr_in address;
            address.sin_family = AF_INET;
            address.sin_addr.s_addr = inet_addr(serverAddress);
            address.sin_port = htons((u_short) atoi(port));
            res = connect(client, (struct sockaddr *) &address, sizeof(address));
            if (res == SOCKET_ERROR) {
                closesocket(client);
                WSACleanup();
                return ENOTCONN;
            } else if (client == INVALID_SOCKET) {
                WSACleanup();
                return ENOTCONN;
            }
            printf("Podlaczono do:  %s:%d\n", serverAddress, atoi(port));
            running = !0;
            //Utworzenie wątku
            DWORD thrdID;
            HANDLE sendThread = CreateThread(NULL, 0, sendThreadFunction, &client, 0, &thrdID);
            if (sendThread) {
                printf("Utworzono watek: %d(ID)\n", thrdID);
            } else {
                return EAGAIN;
            }
            //Oczekiwanie na dane
            char recvbuf[128];
            do {
                res = recv(client, recvbuf, BUFLEN, 0);
                recvbuf[res] = '\0';
                if (res > 0) {
                    printf("Pobrano (%d): %s\n", res, recvbuf);
                    //przechowanie danych w tymczasowym pliku temp.bin
                    saveBin("temp.bin",recvbuf);
                    //odczytanie danych z ramki
                    Frame inputData;
                    if (readDataFromBinary("temp.bin", &inputData) == 1) {
                        return 2;
                    }
                    //sprawdzenie danych
                    if (checkDataIntegrity(&inputData) == 1) {
                        return 3;
                    }

                    //wyświetlenie danych na konsoli
                    float tempRead = readTemperature(&inputData);
                    printf("Odczytana temperatura na podstawie danych z pliku to: %4.3f stC \n", tempRead);
                    if (checkIfInRange(tempRead, UPPER_TEMP_LIMIT, LOWER_TEMP_LIMIT) == 1) {
                        printf("WARNING! Dane z czujnika %lx(hex) wykraczaja poza zakres temperatur <%d, %d>",
                               inputData.temperatureSensorID, LOWER_TEMP_LIMIT, UPPER_TEMP_LIMIT);
                    }
                    return 0;
                } else if (!res) {
                    printf("Polaczenie zakonczone ;)\n");
                    running = 0;
                } else {
                    printf("Odebranie danych nieudane: %d\n", WSAGetLastError());
                    running = 0;
                }
            } while (running && res > 0);
            running = 0;
            //Zamknięcie wątku
            CloseHandle(sendThread);
            res = shutdown(client, SD_BOTH);
            if (res == SOCKET_ERROR) {
                closesocket(client);
                WSACleanup();
                return EAGAIN;
            }
            closesocket(client);
            WSACleanup();
        }
        default:
            return EINVAL;

        }
}

DWORD WINAPI sendThreadFunction(LPVOID lpParam) {
    SOCKET client = *(SOCKET *) lpParam;
    char sendbuf[BUFLEN];
    int sendbuflen, res;
    while (running) {
        scanf("%s", sendbuf);
        if (!running) {
            break;
        }
        sendbuflen = strlen(sendbuf);
        res = send(client, sendbuf, sendbuflen, 0);
        if (res != sendbuflen) {
            printf("Send failed.");
            break;
        } else if (!memcmp(sendbuf, "/leave", 6)) {
            running = 0;
            break;
        }
    }
    return 0;
}