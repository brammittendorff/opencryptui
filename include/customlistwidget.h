#ifndef CUSTOMLISTWIDGET_H
#define CUSTOMLISTWIDGET_H

#include <QListWidget>
#include <QStringList>
#include <QKeyEvent>
#include <QMenu>
#include <QPushButton>

class CustomListWidget : public QListWidget
{
    Q_OBJECT

public:
    explicit CustomListWidget(QWidget *parent = nullptr);

    QStringList getAllItems() const;
    void addItem(const QString &label);

protected:
    void keyPressEvent(QKeyEvent *event) override;
    bool eventFilter(QObject *obj, QEvent *event) override;

private slots:
    void showContextMenu(const QPoint &pos);
    void removeSelectedItem();
    void removeItem();

private:
    QMenu *contextMenu;
    void setupItemWidget(QListWidgetItem *item, const QString &text);
};

#endif // CUSTOMLISTWIDGET_H