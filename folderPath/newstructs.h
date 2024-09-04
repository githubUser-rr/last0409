#ifndef NEWSTRUCTS_H
#define NEWSTRUCTS_H

#include <QObject>
#include <QString>
#include <QVector>
#include <QStringList>
#include <QDateTime>




struct strPacketInfo{
    QString sourceIP;
    QString destIP;
    QString sourceMac;
    QString destMac;

    uint16_t sourcePort;
    uint16_t destPort;

    QString protocol ;
    QString timestamp ;
    int packetLen;
    QString message ;
    QString smtpSender;
    QString smtpRecipient;
    QString mailBody;
};

struct strSessıonInfo{
    QString sourceIP;
    QString destIP;
    uint16_t sourcePort;
    uint16_t destPort;
    int streamIndex;
    int packetCount;
    int packetsLen;
    int sourceTodest;
    int sourceTodestLen;
    int destToSource;
    int destToSourceLen;
    QString startTime;
    QString endTime;
    QVector<int> packetIndex;
    QStringList messages;

    QString protocol;
    QString smtpSender;
    QString smtpRecipient;
    QStringList mailB;

};

struct sipSessionInfo{
    QString message;
    QString cId;
    QString Ip;
    QString mediaData;
    QString port;
    QDateTime tms;


    bool operator==(const sipSessionInfo &other) const {
        return cId == other.cId;
    }


    friend uint qHash(const sipSessionInfo &key, uint seed) {
        return qHash(key.cId, seed);  // cId üzerinden hash hesaplama
    }
};



#endif // NEWSTRUCTS_H
