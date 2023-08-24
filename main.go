package main

import (
	"fmt"
	"log"
	"postgresmodule"
)

func main() {
	connectionString := "postgres://yourusername:yourpassword@localhost:5432/yourdb"

	module, err := postgresmodule.NewPostgresModule(connectionString)
	if err != nil {
		log.Fatal(err)
	}
	defer module.Close()

	// 示例：插入或更新 Dcount 表
	err = module.InsertOrUpdateDcount("keyword1", 100)
	if err != nil {
		log.Fatal(err)
	}

	// 示例：查询 Dcount 表
	count, err := module.GetDcount("keyword1")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Dcount:", count)

	// 示例：插入或更新 D 表
	err = module.InsertOrUpdateD("l1", "data1")
	if err != nil {
		log.Fatal(err)
	}

	// 示例：查询 D 表
	d, err := module.GetD("l1")
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("D:", d)
}
