package postgresmodule

import (
	"fmt"

	"github.com/go-pg/pg/v10"
	"github.com/go-pg/pg/v10/orm"
)

type Dcount struct {
	Keyword string `pg:",pk"`
	Count   int
}

type D struct {
	L string `pg:",pk"`
	D string
}

type PostgresModule struct {
	db *pg.DB
}

func NewPostgresModule(connectionString string) (*PostgresModule, error) {
	opt, err := pg.ParseURL(connectionString)
	if err != nil {
		return nil, err
	}

	db := pg.Connect(opt)

	return &PostgresModule{db: db}, nil
}

func (p *PostgresModule) Close() {
	p.db.Close()
}

func (p *PostgresModule) UpdateCount(keyword string, count int) error {
	dcount := &Dcount{Keyword: keyword}
	err := p.db.Model(dcount).WherePK().Select()
	if err != nil {
		if err == pg.ErrNoRows {
			// If the record does not exist, create a new one
			dcount.Count = count
			_, err = p.db.Model(dcount).Insert()
			if err != nil {
				return err
			}
		} else {
			return err
		}
	} else {
		// If the record already exists, update the count value
		dcount.Count += count
		_, err = p.db.Model(dcount).WherePK().Update()
		if err != nil {
			return err
		}
	}

	fmt.Printf("Dcount for keyword %s updated to %d\n", keyword, dcount.Count)

	return nil
}

func (p *PostgresModule) GetDcount(keyword string) (int, error) {
	var dcount Dcount
	err := p.db.Model(&dcount).
		Where("keyword = ?", keyword).
		Select()

	if err != nil {
		if err == pg.ErrNoRows {
			return 0, nil // Keyword not found
		}
		return 0, err
	}

	return dcount.Count, nil
}

func (p *PostgresModule) InsertOrUpdateD(l string, d string) error {
	dData := D{
		L: l,
		D: d,
	}

	_, err := p.db.Model(&dData).
		OnConflict("(l) DO UPDATE").
		Insert()

	return err
}

func (p *PostgresModule) GetD(l string) (string, error) {
	var dData D
	err := p.db.Model(&dData).
		Where("l = ?", l).
		Select()

	if err != nil {
		if err == pg.ErrNoRows {
			return "", nil // Key not found
		}
		return "", err
	}

	return dData.D, nil
}

func createTableIfNotExists(db *pg.DB) error {
	// 创建一个新的结构体实例，以便ORM库检查表是否存在
	models := []interface{}{
		(*Dcount)(nil),
		(*D)(nil),
	}
	// 使用DB的Context来执行SchemaCreateTable方法，该方法在表不存在时创建表

	for _, model := range models {
		db.Model(model).CreateTable(&orm.CreateTableOptions{
			Temp:          false,
			FKConstraints: true,
			IfNotExists:   true, // 使用 IfNotExists 选项以防表已经存在
		})
	}

	return nil
}

func SetupDatabase() (*PostgresModule, error) {
	connectionString := "postgres://postgres:postgres@localhost:5432/sse?sslmode=disable"
	module, err := NewPostgresModule(connectionString)
	if err != nil {
		return nil, err
	}

	err = createTableIfNotExists(module.db)
	if err != nil {
		module.Close()
		return nil, err
	}

	return module, nil
}
