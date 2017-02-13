#pragma once

class  Database {
	

public:
	static Database& getInstance()
	{
		static Database    instance; // Guaranteed to be destroyed.
							  // Instantiated on first use.
		return instance;
	}
private:
	Database() {}                    // Constructor? (the {} brackets) are needed here.

							  // C++ 03
							  // ========
							  // Dont forget to declare these two. You want to make sure they
							  // are unacceptable otherwise you may accidentally get copies of
							  // your singleton appearing.
	Database(Database const&);              // Don't Implement
	void operator=(Database const&); // Don't implement

							  // C++ 11
							  // =======
							  // We can use the better technique of deleting the methods
							  // we don't want.
public:
	Database(Database const&) = delete;
	void operator=(Database const&) = delete;

	// Note: Scott Meyers mentions in his Effective Modern
	//       C++ book, that deleted functions should generally
	//       be public as it results in better error messages
	//       due to the compilers behavior to check accessibility
	//       before deleted status
};